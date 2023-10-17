// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pcaconnectorad

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pcaconnectorad"
	awstypes "github.com/aws/aws-sdk-go-v2/service/pcaconnectorad/types"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// Function annotations are used for resource registration to the Provider. DO NOT EDIT.
// @FrameworkResource(name="Template")
// @Tags(identifierAttribute="arn")
func newResourceTemplate(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceTemplate{}

	r.SetDefaultCreateTimeout(30 * time.Minute)
	r.SetDefaultUpdateTimeout(30 * time.Minute)
	r.SetDefaultDeleteTimeout(30 * time.Minute)

	return r, nil
}

const (
	ResNameTemplate = "Template"
)

type resourceTemplate struct {
	framework.ResourceWithConfigure
	framework.WithTimeouts
}

func (r *resourceTemplate) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_pcaconnectorad_template"
}

func (r *resourceTemplate) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"arn": framework.ARNAttributeComputedOnly(),
			"connector_arn": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": framework.IDAttribute(),
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					// stringvalidator.RegexMatches(regexp.MustCompile(`^(?!^\s+$)((?![\x5c'\x2b,;<=>#\x22])([\x20-\x7E]))+$`), ""),
					stringvalidator.LengthAtLeast(1),
					stringvalidator.LengthAtMost(64),
				},

				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"object_identifier": schema.StringAttribute{
				Computed: true,
			},
			"policy_schema": schema.Int64Attribute{
				Required: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.Between(2, 4),
				},
			},
			"revision": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"major_revision": types.Int64Type,
					"minor_revision": types.Int64Type,
				},
				Computed: true,
			},
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
		},
		Blocks: map[string]schema.Block{
			"definition": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
						Validators: []validator.String{
							stringvalidator.OneOf(hashAlgorithmStrings()...),
						},
					},
					"superseded_templates": schema.SetAttribute{
						Optional:    true,
						ElementType: types.StringType,

						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
							setvalidator.SizeAtMost(100),
							setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, 64)),
							// setvalidator.ValueStringsAre(stringvalidator.RegexMatches(regexp.MustCompile(`^(?!^\s+$)((?![\x5c'\x2b,;<=>#\x22])([\x20-\x7E]))+$`), "must be a valid template name")),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"certificate_validity": schema.SingleNestedBlock{
						Blocks: map[string]schema.Block{
							"renewal_period":  validityPeriodBlock(),
							"validity_period": validityPeriodBlock(),
						},
					},
					"enrollment_flags":       enrollmentFlagsBlock(),
					"extensions":             extensionsBlock(),
					"general_flags":          generalFlagsBlock(),
					"private_key_attributes": privateKeyAttributesBlock(),
					"private_key_flags":      privateKeyFlagsBlock(),
					"subject_name_flags":     subjectNameFlagsBlock(),
				},
			},
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r resourceTemplate) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data resourceTemplateData

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	opts := basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    false,
		UnhandledUnknownAsEmpty: false,
	}

	var definition definitionData
	data.Definition.As(ctx, definition, opts)
	policySchema := data.PolicySchema.ValueInt64()
	policySchemaSummary := fmt.Sprintf("Invalid attribute for policy schema %d", policySchema)

	switch policySchema {
	case 2:
		if !definition.HashAlgorithm.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("definition"), policySchemaSummary,
				"hash_algorithm cannot be configured with policy_schema version 2")
		}
		// stringvalidator.OneOf(validityPeriodTypeStrings()...)
		// resp.Diagnostics.AddAttributeError()
		// if definition.PrivateKeyFlags.ClientVersion.ValueString()

	case 3:
	case 4:

	}

	// // If attribute_one is not configured, return without warning.
	// if data.AttributeOne.IsNull() || data.AttributeOne.IsUnknown() {
	//     return
	// }

	// // If attribute_two is not null, return without warning.
	// if !data.AttributeTwo.IsNull() {
	//     return
	// }

	// resp.Diagnostics.AddAttributeWarning(
	//     path.Root("attribute_two"),
	//     "Missing Attribute Configuration",
	//     "Expected attribute_two to be configured with attribute_one. "+
	//         "The resource may return unexpected results.",
	// )
}

func (r *resourceTemplate) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var plan resourceTemplateData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.CreateTemplateInput{
		ConnectorArn: aws.String(plan.ConnectorARN.ValueString()),
		Name:         aws.String(plan.Name.ValueString()),
		Tags:         getTagsIn(ctx),
	}

	opts := basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    false,
		UnhandledUnknownAsEmpty: false,
	}

	var def definitionData
	resp.Diagnostics.Append(plan.Definition.As(ctx, def, opts)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policySchema := plan.PolicySchema.ValueInt64()

	var d diag.Diagnostics
	in.Definition, d = expandDefinition(ctx, policySchema, def)
	resp.Diagnostics.Append(d...)

	out, err := conn.CreateTemplate(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameTemplate, plan.Name.String(), err),
			err.Error(),
		)
		return
	}
	if out == nil || out.TemplateArn == nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameTemplate, plan.Name.String(), nil),
			errors.New("empty output").Error(),
		)
		return
	}

	plan.ARN = flex.StringToFramework(ctx, out.TemplateArn)
	plan.ID = flex.StringToFramework(ctx, out.TemplateArn)

	createTimeout := r.CreateTimeout(ctx, plan.Timeouts)
	_, err = waitTemplateCreated(ctx, conn, plan.ID.ValueString(), createTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForCreation, ResNameTemplate, plan.Name.String(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceTemplate) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceTemplateData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findTemplateByID(ctx, conn, state.ID.ValueString())

	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionSetting, ResNameTemplate, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	state.ARN = flex.StringToFramework(ctx, out.Arn)
	state.ConnectorARN = flex.StringToFramework(ctx, out.ConnectorArn)
	state.ID = flex.StringToFramework(ctx, out.Arn)
	state.Name = flex.StringToFramework(ctx, out.Name)
	state.ObjectIdentifier = flex.StringToFramework(ctx, out.ObjectIdentifier)
	state.PolicySchema = flex.Int32ToFramework(ctx, out.PolicySchema)

	// tagin := &pcaconnectorad.ListTagsForResourceInput{
	// 	ResourceArn: aws.String(state.ID.String()),
	// }
	// tagout, err := conn.ListTagsForResource(ctx, tagin)
	// resp.Diagnostics.AddError("Error with ListTagsForResource", err.Error())
	// if tagout.Tags != nil {
	// 	state.TagsAll = flex.FlattenFrameworkStringValueMap(ctx, tagout.Tags)
	// 	state.Tags = flex.FlattenFrameworkStringValueMap(ctx, tagout.Tags)
	// }

	revision, d := flattenRevision(ctx, out.Revision)
	resp.Diagnostics.Append(d...)
	state.Revision = revision

	definition, d := flattenDefinition(ctx, out.Definition)
	resp.Diagnostics.Append(d...)
	state.Definition = definition

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceTemplate) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var plan, state resourceTemplateData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Name.Equal(state.Name) {

		in := &pcaconnectorad.UpdateTemplateInput{
			TemplateArn: aws.String(plan.ID.ValueString()),
		}

		out, err := conn.UpdateTemplate(ctx, in)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionUpdating, ResNameTemplate, plan.ID.String(), err),
				err.Error(),
			)
			return
		}
		if out == nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionUpdating, ResNameTemplate, plan.ID.String(), nil),
				errors.New("empty output").Error(),
			)
			return
		}

		// TIP: Using the output from the update function, re-set any computed attributes
		// plan.ARN = flex.StringToFramework(ctx, out.Template.Arn)
		// plan.ID = flex.StringToFramework(ctx, out.Template.TemplateId)
	}

	updateTimeout := r.UpdateTimeout(ctx, plan.Timeouts)
	_, err := waitTemplateUpdated(ctx, conn, plan.ID.ValueString(), updateTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForUpdate, ResNameTemplate, plan.ID.String(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceTemplate) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceTemplateData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.DeleteTemplateInput{
		TemplateArn: aws.String(state.ID.ValueString()),
	}

	_, err := conn.DeleteTemplate(ctx, in)

	if err != nil {
		var nfe *awstypes.ResourceNotFoundException
		if errors.As(err, &nfe) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionDeleting, ResNameTemplate, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	deleteTimeout := r.DeleteTimeout(ctx, state.Timeouts)
	_, err = waitTemplateDeleted(ctx, conn, state.ID.ValueString(), deleteTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForDeletion, ResNameTemplate, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceTemplate) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
func (r *resourceTemplate) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	r.SetTagsAll(ctx, request, response)
}

func waitTemplateCreated(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*awstypes.Template, error) {
	stateConf := &retry.StateChangeConf{
		Pending:                   []string{},
		Target:                    []string{string(awstypes.TemplateStatusActive)},
		Refresh:                   statusTemplate(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*awstypes.Template); ok {
		return out, err
	}

	return nil, err
}

func waitTemplateUpdated(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*awstypes.Template, error) {
	stateConf := &retry.StateChangeConf{
		Pending:                   []string{},
		Target:                    []string{string(awstypes.TemplateStatusActive)},
		Refresh:                   statusTemplate(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*awstypes.Template); ok {
		return out, err
	}

	return nil, err
}

func waitTemplateDeleted(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*awstypes.Template, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{string(awstypes.TemplateStatusDeleting), string(awstypes.TemplateStatusActive)},
		Target:  []string{},
		Refresh: statusTemplate(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*awstypes.Template); ok {
		return out, err
	}

	return nil, err
}

func statusTemplate(ctx context.Context, conn *pcaconnectorad.Client, id string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		out, err := findTemplateByID(ctx, conn, id)
		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return out, aws.ToString((*string)(&out.Status)), nil
	}
}

func findTemplateByID(ctx context.Context, conn *pcaconnectorad.Client, id string) (*awstypes.Template, error) {
	in := &pcaconnectorad.GetTemplateInput{
		TemplateArn: aws.String(id),
	}

	out, err := conn.GetTemplate(ctx, in)
	if err != nil {
		var nfe *awstypes.ResourceNotFoundException
		if errors.As(err, &nfe) {
			return nil, &retry.NotFoundError{
				LastError:   err,
				LastRequest: in,
			}
		}

		return nil, err
	}

	if out == nil || out.Template == nil {
		return nil, tfresource.NewEmptyResultError(in)
	}

	return out.Template, nil
}

type resourceTemplateData struct {
	ARN              types.String   `tfsdk:"arn"`
	ConnectorARN     types.String   `tfsdk:"connector_arn"`
	Definition       types.Object   `tfsdk:"definition"`
	ID               types.String   `tfsdk:"id"`
	Name             types.String   `tfsdk:"name"`
	ObjectIdentifier types.String   `tfsdk:"object_identifier"`
	PolicySchema     types.Int64    `tfsdk:"policy_schema"`
	Revision         types.Object   `tfsdk:"revision"`
	Tags             types.Map      `tfsdk:"tags"`
	TagsAll          types.Map      `tfsdk:"tags_all"`
	Timeouts         timeouts.Value `tfsdk:"timeouts"`
}

// type commonDefinitionData struct {
// 	CertificateValidity certificateValidityData `tfsdk:"certificate_validity"`
// 	EnrollmentFlags     enrollmentFlagsData     `tfsdk:"enrollment_flags"`
// 	Extensions          extensionsData          `tfsdk:"extensions"`
// 	GeneralFlags        generalFlagsData        `tfsdk:"general_flags"`
// 	SubjectNameFlags    subjectNameFlagsData    `tfsdk:"subject_name_flags"`
// 	SupersededTemplates types.Set               `tfsdk:"superseded_templates"`
// }

// type definitionV2Data struct {
// 	commonDefinitionData
// 	PrivateKeyAttributes privateKeyAttributesV2Data `tfsdk:"private_key_attributes"`
// 	PrivateKeyFlags      privateKeyFlagsV2Data      `tfsdk:"private_key_flags"`
// }

// type definitionV3Data struct {
// 	commonDefinitionData
// 	HashAlgorithm        types.String                 `tfsdk:"hash_algorithm"`
// 	PrivateKeyAttributes privateKeyAttributesV3V4Data `tfsdk:"private_key_attributes"`
// 	PrivateKeyFlags      privateKeyFlagsV3Data        `tfsdk:"private_key_flags"`
// }

// type definitionV4Data struct {
// 	commonDefinitionData
// 	HashAlgorithm        types.String                 `tfsdk:"hash_algorithm"`
// 	PrivateKeyAttributes privateKeyAttributesV3V4Data `tfsdk:"private_key_attributes"`
// 	PrivateKeyFlags      privateKeyFlagsV4Data        `tfsdk:"private_key_flags"`
// }

type definitionData struct {
	CertificateValidity  certificateValidityData  `tfsdk:"certificate_validity"`
	EnrollmentFlags      enrollmentFlagsData      `tfsdk:"enrollment_flags"`
	Extensions           extensionsData           `tfsdk:"extensions"`
	GeneralFlags         generalFlagsData         `tfsdk:"general_flags"`
	HashAlgorithm        types.String             `tfsdk:"hash_algorithm"`
	PrivateKeyAttributes privateKeyAttributesData `tfsdk:"private_key_attributes"`
	PrivateKeyFlags      privateKeyFlagsData      `tfsdk:"private_key_flags"`
	SubjectNameFlags     subjectNameFlagsData     `tfsdk:"subject_name_flags"`
	SupersededTemplates  types.Set                `tfsdk:"superseded_templates"`
}

type certificateValidityData struct {
	RenewalPeriod  validityPeriodData `tfsdk:"renewal_period"`
	ValidityPeriod validityPeriodData `tfsdk:"validity_period"`
}

type validityPeriodData struct {
	Period     types.Int64  `tfsdk:"period"`
	PeriodType types.String `tfsdk:"period_type"`
}

type enrollmentFlagsData struct {
	EnableKeyReuseOnNtTokenKeysetStorageFull  types.Bool `tfsdk:"enable_key_reuse_on_nt_token_keyset_storage_full"`
	IncludeSymmetricAlgorithms                types.Bool `tfsdk:"include_symmetric_algorithms"`
	NoSecurityExtension                       types.Bool `tfsdk:"no_security_extension"`
	RemoveInvalidCertificateFromPersonalStore types.Bool `tfsdk:"remove_invalid_certificate_from_personal_store"`
	UserInteractionRequired                   types.Bool `tfsdk:"user_interaction_required"`
}

type extensionsData struct {
	KeyUsage            keyUsageData            `tfsdk:"key_usage"`
	ApplicationPolicies applicationPoliciesData `tfsdk:"application_policies"`
}

type keyUsageData struct {
	Critical   types.Bool        `tfsdk:"critical"`
	UsageFlags keyUsageFlagsData `tfsdk:"usage_flags"`
}

type keyUsageFlagsData struct {
	DataEncipherment types.Bool `tfsdk:"data_encipherment"`
	DigitalSignature types.Bool `tfsdk:"digital_signature"`
	KeyAgreement     types.Bool `tfsdk:"key_agreement"`
	KeyEncipherment  types.Bool `tfsdk:"key_encipherment"`
	NonRepudiation   types.Bool `tfsdk:"non_repudiation"`
}

type applicationPoliciesData struct {
	Policies types.Set  `tfsdk:"policies"`
	Critical types.Bool `tfsdk:"critical"`
}

type policiesData struct {
	PolicyObjectIdentifier types.String `tfsdk:"policy_object_identifier"`
	PolicyType             types.String `tfsdk:"policy_type"`
}

type generalFlagsData struct {
	AutoEnrollment types.Bool `tfsdk:"auto_enrollment"`
	MachineType    types.Bool `tfsdk:"machine_type"`
}

// type privateKeyAttributesV2Data struct {
// 	KeySpec          types.String `tfsdk:"key_spec"`
// 	MinimalKeyLength types.Int64  `tfsdk:"minimal_key_length"`
// 	CryptoProviders  types.Set    `tfsdk:"crypto_providers"`
// }

// type privateKeyAttributesV3V4Data struct {
// 	privateKeyAttributesV2Data
// 	Algorithm        types.String         `tfsdk:"algorithm"`
// 	KeyUsageProperty keyUsagePropertyData `tfsdk:"key_usage_property"`
// }

type privateKeyAttributesData struct {
	KeySpec          types.String         `tfsdk:"key_spec"`
	MinimalKeyLength types.Int64          `tfsdk:"minimal_key_length"`
	CryptoProviders  types.Set            `tfsdk:"crypto_providers"`
	Algorithm        types.String         `tfsdk:"algorithm"`
	KeyUsageProperty keyUsagePropertyData `tfsdk:"key_usage_property"`
}

type keyUsagePropertyData struct {
	PropertyFlags keyUsagePropertyFlagsData `tfsdk:"property_flags"`
	PropertyType  types.String              `tfsdk:"property_type"`
}

type keyUsagePropertyFlagsData struct {
	Decrypt      types.Bool `tfsdk:"decrypt"`
	KeyAgreement types.Bool `tfsdk:"key_agreement"`
	Sign         types.Bool `tfsdk:"sign"`
}

// type privateKeyFlagsV2Data struct {
// 	ClientVersion               types.String `tfsdk:"client_version"`
// 	ExportableKey               types.Bool   `tfsdk:"exportable_key"`
// 	StrongKeyProtectionRequired types.Bool   `tfsdk:"strong_key_protection_required"`
// }

// type privateKeyFlagsV3Data struct {
// 	privateKeyFlagsV2Data
// 	RequireAlternateSignatureAlgorithm types.Bool `tfsdk:"require_alternate_signature_algorithm"`
// }

// type privateKeyFlagsV4Data struct {
// 	privateKeyFlagsV3Data
// 	RequireSameKeyRenewal types.Bool `tfsdk:"require_same_key_renewal"`
// 	UseLegacyProvider     types.Bool `tfsdk:"use_legacy_provider"`
// }

type privateKeyFlagsData struct {
	ClientVersion                      types.String `tfsdk:"client_version"`
	ExportableKey                      types.Bool   `tfsdk:"exportable_key"`
	RequireAlternateSignatureAlgorithm types.Bool   `tfsdk:"require_alternate_signature_algorithm"`
	RequireSameKeyRenewal              types.Bool   `tfsdk:"require_same_key_renewal"`
	StrongKeyProtectionRequired        types.Bool   `tfsdk:"strong_key_protection_required"`
	UseLegacyProvider                  types.Bool   `tfsdk:"use_legacy_provider"`
}

type subjectNameFlagsData struct {
	RequireCommonName       types.Bool `tfsdk:"require_common_name"`
	RequireDirectoryPath    types.Bool `tfsdk:"require_directory_path"`
	RequireDnsAsCn          types.Bool `tfsdk:"require_dns_as_cn"`
	RequireEmail            types.Bool `tfsdk:"require_email"`
	SanRequireDirectoryGuid types.Bool `tfsdk:"san_require_directory_guid"`
	SanRequireDns           types.Bool `tfsdk:"san_require_dns"`
	SanRequireDomainDns     types.Bool `tfsdk:"san_require_domain_dns"`
	SanRequireEmail         types.Bool `tfsdk:"san_require_email"`
	SanRequireSpn           types.Bool `tfsdk:"san_require_spn"`
	SanRequireUpn           types.Bool `tfsdk:"san_require_upn"`
}

// var definitionV2AttrTypes = map[string]attr.Type{
// 	"certificate_validity": types.ObjectType{
// 		AttrTypes: certificateValidityAttrTypes,
// 	},
// 	"enrollment_flags": types.ObjectType{
// 		AttrTypes: enrollmentFlagsAttrTypes,
// 	},
// 	"extensions": types.ObjectType{
// 		AttrTypes: extensionsAttrTypes,
// 	},
// 	"general_flags": types.ObjectType{
// 		AttrTypes: generalFlagsAttrTypes,
// 	},
// 	"private_key_attributes": types.ObjectType{
// 		AttrTypes: commonPrivateKeyAttributesAttrTypes,
// 	},
// 	"private_key_flags": types.ObjectType{
// 		AttrTypes: commonprivateKeyFlagsAttrTypes,
// 	},
// 	"subject_name_flags": types.ObjectType{
// 		AttrTypes: subjectNameFlagsAttrTypes,
// 	},
// 	"superseded_templates": types.SetType{
// 		ElemType: types.StringType,
// 	},
// }

var definitionAttrTypes = map[string]attr.Type{
	"certificate_validity": types.ObjectType{
		AttrTypes: certificateValidityAttrTypes,
	},
	"enrollment_flags": types.ObjectType{
		AttrTypes: enrollmentFlagsAttrTypes,
	},
	"extensions": types.ObjectType{
		AttrTypes: extensionsAttrTypes,
	},
	"general_flags": types.ObjectType{
		AttrTypes: generalFlagsAttrTypes,
	},
	"hash_algorithm": types.StringType,
	"private_key_attributes": types.ObjectType{
		AttrTypes: privateKeyAttributesAttrTypes,
	},
	"private_key_flags": types.ObjectType{
		AttrTypes: privateKeyFlagsAttrTypes,
	},
	"subject_name_flags": types.ObjectType{
		AttrTypes: subjectNameFlagsAttrTypes,
	},
	"superseded_templates": types.SetType{
		ElemType: types.StringType,
	},
}

var validityPeriodAttrTypes = map[string]attr.Type{
	"period":      types.Int64Type,
	"period_type": types.StringType,
}

var certificateValidityAttrTypes = map[string]attr.Type{
	"renewal_period": types.ObjectType{
		AttrTypes: validityPeriodAttrTypes,
	},
	"validity_period": types.ObjectType{
		AttrTypes: validityPeriodAttrTypes,
	},
}

var enrollmentFlagsAttrTypes = map[string]attr.Type{
	"enable_key_reuse_on_nt_token_keyset_storage_full": types.BoolType,
	"include_symmetric_algorithms":                     types.BoolType,
	"no_security_extension":                            types.BoolType,
	"remove_invalid_certificate_from_personal_store":   types.BoolType,
	"user_interaction_required":                        types.BoolType,
}

var usageFlagsAttrTypes = map[string]attr.Type{
	"data_encipherment": types.BoolType,
	"digital_signature": types.BoolType,
	"key_agreement":     types.BoolType,
	"key_encipherment":  types.BoolType,
	"non_repudiation":   types.BoolType,
}

var keyUsageAttrTypes = map[string]attr.Type{
	"critical": types.BoolType,
	"usage_flags": types.ObjectType{
		AttrTypes: usageFlagsAttrTypes,
	},
}

var applicationPoliciesAttrTypes = map[string]attr.Type{
	"policies": types.SetType{
		ElemType: types.ObjectType{
			AttrTypes: policiesAttrTypes,
		},
	},
	"critical": types.BoolType,
}

var policiesAttrTypes = map[string]attr.Type{
	"policy_object_identifier": types.StringType,
	"policy_type":              types.StringType,
}

var extensionsAttrTypes = map[string]attr.Type{
	"key_usage": types.ObjectType{
		AttrTypes: keyUsageAttrTypes,
	},
	"application_policies": types.ObjectType{
		AttrTypes: applicationPoliciesAttrTypes,
	},
}

var generalFlagsAttrTypes = map[string]attr.Type{
	"auto_enrollment": types.BoolType,
	"machine_type":    types.BoolType,
}

var keyUsagePropertyFlagsAttrTypes = map[string]attr.Type{
	"decrypt":       types.BoolType,
	"key_agreement": types.BoolType,
	"sign":          types.BoolType,
}

var keyUsagePropertyAttrTypes = map[string]attr.Type{
	"property_flags": types.ObjectType{
		AttrTypes: keyUsagePropertyFlagsAttrTypes,
	},
	"property_type": types.StringType,
}

var privateKeyAttributesAttrTypes = map[string]attr.Type{
	"algorithm": types.StringType,
	"crypto_providers": types.SetType{
		ElemType: types.StringType,
	},
	"key_usage_property": types.ObjectType{
		AttrTypes: keyUsagePropertyAttrTypes,
	},
	"key_spec":           types.StringType,
	"minimal_key_length": types.Int64Type,
}

var privateKeyFlagsAttrTypes = map[string]attr.Type{
	"client_version":                        types.StringType,
	"exportable_key":                        types.BoolType,
	"require_alternate_signature_algorithm": types.BoolType,
	"require_same_key_renewal":              types.BoolType,
	"strong_key_protection_required":        types.BoolType,
	"use_legacy_provider":                   types.BoolType,
}

var subjectNameFlagsAttrTypes = map[string]attr.Type{
	"require_common_name":        types.BoolType,
	"require_directory_path":     types.BoolType,
	"require_dns_as_cn":          types.BoolType,
	"require_email":              types.BoolType,
	"san_require_directory_guid": types.BoolType,
	"san_require_dns":            types.BoolType,
	"san_require_domain_dns":     types.BoolType,
	"san_require_email":          types.BoolType,
	"san_require_spn":            types.BoolType,
	"san_require_upn":            types.BoolType,
}

var revisionAttrTypes = map[string]attr.Type{
	"major_revision": types.Int64Type,
	"minor_revision": types.Int64Type,
}

func applicationPolicyTypeStrings() []string {
	var s []string

	values := new(awstypes.ApplicationPolicyType).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func validityPeriodTypeStrings() []string {
	var s []string

	values := new(awstypes.ValidityPeriodType).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func keySpecStrings() []string {
	var s []string

	values := new(awstypes.KeySpec).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func clientCompatibilityV2Strings() []string {
	var s []string

	values := new(awstypes.ClientCompatibilityV2).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func validityPeriodBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"period": schema.Int64Attribute{
				Required: true,
				Validators: []validator.Int64{
					int64validator.Between(1, 8766000),
				},
			},
			"period_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(validityPeriodTypeStrings()...),
				},
			},
		},
	}
}

func enrollmentFlagsBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"enable_key_reuse_on_nt_token_keyset_storage_full": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"include_symmetric_algorithms": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"no_security_extension": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"remove_invalid_certificate_from_personal_store": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"user_interaction_required": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
		},
	}
}

func extensionsBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Blocks: map[string]schema.Block{
			"key_usage": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"critical": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
				Blocks: map[string]schema.Block{
					"usage_flags": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"data_encipherment": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"digital_signature": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"key_agreement": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"key_encipherment": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
							"non_repudiation": schema.BoolAttribute{
								Optional: true,
								Computed: true,
							},
						},
					},
				},
			},
			"application_policies": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"critical": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
				Blocks: map[string]schema.Block{
					"policies": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"policy_object_identifier": schema.StringAttribute{
									Optional: true,
									Validators: []validator.String{
										stringvalidator.LengthBetween(1, 64),
										stringvalidator.RegexMatches(regexp.MustCompile(`^([0-2])\.([0-9]|([0-3][0-9]))(\.([0-9]+)){0,126}$`), "must be a valid policy object identifier"),
									},
								},
								"policy_type": schema.StringAttribute{
									Optional: true,
									Validators: []validator.String{
										stringvalidator.OneOf(applicationPolicyTypeStrings()...),
									},
								},
							},
						},
						Validators: []validator.Set{
							setvalidator.SizeBetween(1, 100),
						},
					},
				},
			},
		},
	}
}

func generalFlagsBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"auto_enrollment": schema.BoolAttribute{
				Optional: true,
			},
			"machine_type": schema.BoolAttribute{
				Optional: true,
			},
		},
	}
}

func privateKeyAttributesBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"algorithm": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf(algorithmStrings()...),
				},
			},
			"crypto_providers": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 100),
					setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, 100)),
				},
			},
			"key_spec": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(keySpecStrings()...),
				},
			},
			"minimal_key_length": schema.Int64Attribute{
				Required: true,
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"key_usage_property": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"property_type": schema.StringAttribute{
						Optional: true,
						Validators: []validator.String{
							stringvalidator.OneOf(keyUsagePropertyTypeStrings()...),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"property_flags": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"decrypt": schema.BoolAttribute{
								Optional: true,
							},
							"key_agreement": schema.BoolAttribute{
								Optional: true,
							},
							"sign": schema.BoolAttribute{
								Optional: true,
							},
						},
					},
				},
			},
		},
	}
}

func privateKeyFlagsBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"client_version": schema.StringAttribute{
				Required: true,
			},
			"exportable_key": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"require_alternate_signature_algorithm": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"require_same_key_renewal": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"strong_key_protection_required": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"use_legacy_provider": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
		},
	}
}

func subjectNameFlagsBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"require_common_name": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"require_directory_path": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"require_dns_as_cn": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"require_email": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_directory_guid": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_dns": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_domain_dns": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_email": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_spn": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"san_require_upn": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
		},
	}
}

func expandPolicies(polList []policiesData) []awstypes.ApplicationPolicy {
	apiObject := make([]awstypes.ApplicationPolicy, 0)

	for _, pol := range polList {
		if !pol.PolicyObjectIdentifier.IsNull() {
			item := &awstypes.ApplicationPolicyMemberPolicyObjectIdentifier{
				Value: pol.PolicyObjectIdentifier.ValueString(),
			}
			apiObject = append(apiObject, item)

		}
		if !pol.PolicyType.IsNull() {
			item := &awstypes.ApplicationPolicyMemberPolicyType{
				Value: awstypes.ApplicationPolicyType(pol.PolicyType.ValueString()),
			}
			apiObject = append(apiObject, item)
		}
	}

	return apiObject
}

func expandKeyUsageProperty(prop keyUsagePropertyData) awstypes.KeyUsageProperty {
	if prop.PropertyFlags.Decrypt.IsNull() && prop.PropertyFlags.KeyAgreement.IsNull() && prop.PropertyFlags.Sign.IsNull() {
		// None of the property flags are set, so check if the property type is set
		if !prop.PropertyType.IsNull() {
			// Return the property type since it is set
			return &awstypes.KeyUsagePropertyMemberPropertyType{
				Value: awstypes.KeyUsagePropertyType(prop.PropertyType.ValueString()),
			}
		} else {
			// Return nil since neither the property flags nor the property type are set
			return nil
		}
	} else {
		// At least one of the property flags is set, so return the property flags
		return &awstypes.KeyUsagePropertyMemberPropertyFlags{
			Value: awstypes.KeyUsagePropertyFlags{
				Decrypt:      prop.PropertyFlags.Decrypt.ValueBoolPointer(),
				KeyAgreement: prop.PropertyFlags.KeyAgreement.ValueBoolPointer(),
				Sign:         prop.PropertyFlags.Sign.ValueBoolPointer(),
			},
		}
	}
}

func expandDefinition(ctx context.Context, policySchema int64, tfObj definitionData) (awstypes.TemplateDefinition, diag.Diagnostics) {
	var diags diag.Diagnostics

	var cryptoProviders []string
	d := tfObj.PrivateKeyAttributes.CryptoProviders.ElementsAs(ctx, &cryptoProviders, false)
	diags.Append(d...)

	var policiesData []policiesData
	d = tfObj.Extensions.ApplicationPolicies.Policies.ElementsAs(ctx, &policiesData, false)
	diags.Append(d...)

	var minimalKeyLength *int32
	if !tfObj.PrivateKeyAttributes.MinimalKeyLength.IsNull() {
		minimalKeyLength = aws.Int32(int32(tfObj.PrivateKeyAttributes.MinimalKeyLength.ValueInt64()))
	}

	var supersededTemplates []string
	d = tfObj.SupersededTemplates.ElementsAs(ctx, &supersededTemplates, false)
	diags.Append(d...)

	switch policySchema {
	case 2:
		apiObject := &awstypes.TemplateDefinitionMemberTemplateV2{
			Value: awstypes.TemplateV2{
				CertificateValidity: &awstypes.CertificateValidity{
					RenewalPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.RenewalPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.RenewalPeriod.PeriodType.ValueString()),
					},
					ValidityPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.ValidityPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.ValidityPeriod.PeriodType.ValueString()),
					},
				},
				EnrollmentFlags: &awstypes.EnrollmentFlagsV2{
					EnableKeyReuseOnNtTokenKeysetStorageFull:  tfObj.EnrollmentFlags.EnableKeyReuseOnNtTokenKeysetStorageFull.ValueBoolPointer(),
					IncludeSymmetricAlgorithms:                tfObj.EnrollmentFlags.IncludeSymmetricAlgorithms.ValueBoolPointer(),
					NoSecurityExtension:                       tfObj.EnrollmentFlags.NoSecurityExtension.ValueBoolPointer(),
					RemoveInvalidCertificateFromPersonalStore: tfObj.EnrollmentFlags.RemoveInvalidCertificateFromPersonalStore.ValueBoolPointer(),
					UserInteractionRequired:                   tfObj.EnrollmentFlags.UserInteractionRequired.ValueBoolPointer(),
				},
				Extensions: &awstypes.ExtensionsV2{
					KeyUsage: &awstypes.KeyUsage{
						Critical: tfObj.Extensions.KeyUsage.Critical.ValueBoolPointer(),
						UsageFlags: &awstypes.KeyUsageFlags{
							DataEncipherment: tfObj.Extensions.KeyUsage.UsageFlags.DataEncipherment.ValueBoolPointer(),
							DigitalSignature: tfObj.Extensions.KeyUsage.UsageFlags.DigitalSignature.ValueBoolPointer(),
							KeyAgreement:     tfObj.Extensions.KeyUsage.UsageFlags.KeyAgreement.ValueBoolPointer(),
							KeyEncipherment:  tfObj.Extensions.KeyUsage.UsageFlags.KeyEncipherment.ValueBoolPointer(),
							NonRepudiation:   tfObj.Extensions.KeyUsage.UsageFlags.NonRepudiation.ValueBoolPointer(),
						},
					},
					ApplicationPolicies: &awstypes.ApplicationPolicies{
						Critical: tfObj.Extensions.ApplicationPolicies.Critical.ValueBoolPointer(),
						Policies: expandPolicies(policiesData),
					},
				},
				GeneralFlags: &awstypes.GeneralFlagsV2{
					AutoEnrollment: tfObj.GeneralFlags.AutoEnrollment.ValueBoolPointer(),
					MachineType:    tfObj.GeneralFlags.MachineType.ValueBoolPointer(),
				},
				PrivateKeyAttributes: &awstypes.PrivateKeyAttributesV2{
					KeySpec:          awstypes.KeySpec(tfObj.PrivateKeyAttributes.KeySpec.ValueString()),
					MinimalKeyLength: minimalKeyLength,
					CryptoProviders:  cryptoProviders,
				},
				PrivateKeyFlags: &awstypes.PrivateKeyFlagsV2{
					ClientVersion:               awstypes.ClientCompatibilityV2(tfObj.PrivateKeyFlags.ClientVersion.ValueString()),
					ExportableKey:               tfObj.PrivateKeyFlags.ExportableKey.ValueBoolPointer(),
					StrongKeyProtectionRequired: tfObj.PrivateKeyFlags.StrongKeyProtectionRequired.ValueBoolPointer(),
				},
				SubjectNameFlags: &awstypes.SubjectNameFlagsV2{
					RequireCommonName:       tfObj.SubjectNameFlags.RequireCommonName.ValueBoolPointer(),
					RequireDirectoryPath:    tfObj.SubjectNameFlags.RequireDirectoryPath.ValueBoolPointer(),
					RequireDnsAsCn:          tfObj.SubjectNameFlags.RequireDnsAsCn.ValueBoolPointer(),
					RequireEmail:            tfObj.SubjectNameFlags.RequireEmail.ValueBoolPointer(),
					SanRequireDirectoryGuid: tfObj.SubjectNameFlags.SanRequireDirectoryGuid.ValueBoolPointer(),
					SanRequireDns:           tfObj.SubjectNameFlags.SanRequireDns.ValueBoolPointer(),
					SanRequireDomainDns:     tfObj.SubjectNameFlags.SanRequireDomainDns.ValueBoolPointer(),
					SanRequireEmail:         tfObj.SubjectNameFlags.SanRequireEmail.ValueBoolPointer(),
					SanRequireSpn:           tfObj.SubjectNameFlags.SanRequireSpn.ValueBoolPointer(),
					SanRequireUpn:           tfObj.SubjectNameFlags.SanRequireUpn.ValueBoolPointer(),
				},
				SupersededTemplates: supersededTemplates,
			},
		}
		return apiObject, diags
	case 3:
		apiObject := &awstypes.TemplateDefinitionMemberTemplateV3{
			Value: awstypes.TemplateV3{
				CertificateValidity: &awstypes.CertificateValidity{
					RenewalPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.RenewalPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.RenewalPeriod.PeriodType.ValueString()),
					},
					ValidityPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.ValidityPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.ValidityPeriod.PeriodType.ValueString()),
					},
				},
				EnrollmentFlags: &awstypes.EnrollmentFlagsV3{
					EnableKeyReuseOnNtTokenKeysetStorageFull:  tfObj.EnrollmentFlags.EnableKeyReuseOnNtTokenKeysetStorageFull.ValueBoolPointer(),
					IncludeSymmetricAlgorithms:                tfObj.EnrollmentFlags.IncludeSymmetricAlgorithms.ValueBoolPointer(),
					NoSecurityExtension:                       tfObj.EnrollmentFlags.NoSecurityExtension.ValueBoolPointer(),
					RemoveInvalidCertificateFromPersonalStore: tfObj.EnrollmentFlags.RemoveInvalidCertificateFromPersonalStore.ValueBoolPointer(),
					UserInteractionRequired:                   tfObj.EnrollmentFlags.UserInteractionRequired.ValueBoolPointer(),
				},
				Extensions: &awstypes.ExtensionsV3{
					KeyUsage: &awstypes.KeyUsage{
						Critical: tfObj.Extensions.KeyUsage.Critical.ValueBoolPointer(),
						UsageFlags: &awstypes.KeyUsageFlags{
							DataEncipherment: tfObj.Extensions.KeyUsage.UsageFlags.DataEncipherment.ValueBoolPointer(),
							DigitalSignature: tfObj.Extensions.KeyUsage.UsageFlags.DigitalSignature.ValueBoolPointer(),
							KeyAgreement:     tfObj.Extensions.KeyUsage.UsageFlags.KeyAgreement.ValueBoolPointer(),
							KeyEncipherment:  tfObj.Extensions.KeyUsage.UsageFlags.KeyEncipherment.ValueBoolPointer(),
							NonRepudiation:   tfObj.Extensions.KeyUsage.UsageFlags.NonRepudiation.ValueBoolPointer(),
						},
					},
					ApplicationPolicies: &awstypes.ApplicationPolicies{
						Critical: tfObj.Extensions.ApplicationPolicies.Critical.ValueBoolPointer(),
						Policies: expandPolicies(policiesData),
					},
				},
				GeneralFlags: &awstypes.GeneralFlagsV3{
					AutoEnrollment: tfObj.GeneralFlags.AutoEnrollment.ValueBoolPointer(),
					MachineType:    tfObj.GeneralFlags.MachineType.ValueBoolPointer(),
				},
				HashAlgorithm: awstypes.HashAlgorithm(tfObj.HashAlgorithm.ValueString()),
				PrivateKeyAttributes: &awstypes.PrivateKeyAttributesV3{
					Algorithm:        awstypes.PrivateKeyAlgorithm(tfObj.PrivateKeyAttributes.Algorithm.ValueString()),
					CryptoProviders:  cryptoProviders,
					KeySpec:          awstypes.KeySpec(tfObj.PrivateKeyAttributes.KeySpec.ValueString()),
					KeyUsageProperty: expandKeyUsageProperty(tfObj.PrivateKeyAttributes.KeyUsageProperty),
					MinimalKeyLength: minimalKeyLength,
				},
				PrivateKeyFlags: &awstypes.PrivateKeyFlagsV3{
					ClientVersion:                      awstypes.ClientCompatibilityV3(tfObj.PrivateKeyFlags.ClientVersion.ValueString()),
					ExportableKey:                      tfObj.PrivateKeyFlags.ExportableKey.ValueBoolPointer(),
					RequireAlternateSignatureAlgorithm: tfObj.PrivateKeyFlags.RequireAlternateSignatureAlgorithm.ValueBoolPointer(),
					StrongKeyProtectionRequired:        tfObj.PrivateKeyFlags.StrongKeyProtectionRequired.ValueBoolPointer(),
				},
				SubjectNameFlags: &awstypes.SubjectNameFlagsV3{
					RequireCommonName:       tfObj.SubjectNameFlags.RequireCommonName.ValueBoolPointer(),
					RequireDirectoryPath:    tfObj.SubjectNameFlags.RequireDirectoryPath.ValueBoolPointer(),
					RequireDnsAsCn:          tfObj.SubjectNameFlags.RequireDnsAsCn.ValueBoolPointer(),
					RequireEmail:            tfObj.SubjectNameFlags.RequireEmail.ValueBoolPointer(),
					SanRequireDirectoryGuid: tfObj.SubjectNameFlags.SanRequireDirectoryGuid.ValueBoolPointer(),
					SanRequireDns:           tfObj.SubjectNameFlags.SanRequireDns.ValueBoolPointer(),
					SanRequireDomainDns:     tfObj.SubjectNameFlags.SanRequireDomainDns.ValueBoolPointer(),
					SanRequireEmail:         tfObj.SubjectNameFlags.SanRequireEmail.ValueBoolPointer(),
					SanRequireSpn:           tfObj.SubjectNameFlags.SanRequireSpn.ValueBoolPointer(),
					SanRequireUpn:           tfObj.SubjectNameFlags.SanRequireUpn.ValueBoolPointer(),
				},
				SupersededTemplates: supersededTemplates,
			},
		}
		return apiObject, diags
	case 4:
		apiObject := &awstypes.TemplateDefinitionMemberTemplateV4{
			Value: awstypes.TemplateV4{
				CertificateValidity: &awstypes.CertificateValidity{
					RenewalPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.RenewalPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.RenewalPeriod.PeriodType.ValueString()),
					},
					ValidityPeriod: &awstypes.ValidityPeriod{
						Period:     tfObj.CertificateValidity.ValidityPeriod.Period.ValueInt64Pointer(),
						PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.ValidityPeriod.PeriodType.ValueString()),
					},
				},
				EnrollmentFlags: &awstypes.EnrollmentFlagsV4{
					EnableKeyReuseOnNtTokenKeysetStorageFull:  tfObj.EnrollmentFlags.EnableKeyReuseOnNtTokenKeysetStorageFull.ValueBoolPointer(),
					IncludeSymmetricAlgorithms:                tfObj.EnrollmentFlags.IncludeSymmetricAlgorithms.ValueBoolPointer(),
					NoSecurityExtension:                       tfObj.EnrollmentFlags.NoSecurityExtension.ValueBoolPointer(),
					RemoveInvalidCertificateFromPersonalStore: tfObj.EnrollmentFlags.RemoveInvalidCertificateFromPersonalStore.ValueBoolPointer(),
					UserInteractionRequired:                   tfObj.EnrollmentFlags.UserInteractionRequired.ValueBoolPointer(),
				},
				Extensions: &awstypes.ExtensionsV4{
					KeyUsage: &awstypes.KeyUsage{
						Critical: tfObj.Extensions.KeyUsage.Critical.ValueBoolPointer(),
						UsageFlags: &awstypes.KeyUsageFlags{
							DataEncipherment: tfObj.Extensions.KeyUsage.UsageFlags.DataEncipherment.ValueBoolPointer(),
							DigitalSignature: tfObj.Extensions.KeyUsage.UsageFlags.DigitalSignature.ValueBoolPointer(),
							KeyAgreement:     tfObj.Extensions.KeyUsage.UsageFlags.KeyAgreement.ValueBoolPointer(),
							KeyEncipherment:  tfObj.Extensions.KeyUsage.UsageFlags.KeyEncipherment.ValueBoolPointer(),
							NonRepudiation:   tfObj.Extensions.KeyUsage.UsageFlags.NonRepudiation.ValueBoolPointer(),
						},
					},
					ApplicationPolicies: &awstypes.ApplicationPolicies{
						Critical: tfObj.Extensions.ApplicationPolicies.Critical.ValueBoolPointer(),
						Policies: expandPolicies(policiesData),
					},
				},
				GeneralFlags: &awstypes.GeneralFlagsV4{
					AutoEnrollment: tfObj.GeneralFlags.AutoEnrollment.ValueBoolPointer(),
					MachineType:    tfObj.GeneralFlags.MachineType.ValueBoolPointer(),
				},
				HashAlgorithm: awstypes.HashAlgorithm(tfObj.HashAlgorithm.ValueString()),
				PrivateKeyAttributes: &awstypes.PrivateKeyAttributesV4{
					Algorithm:        awstypes.PrivateKeyAlgorithm(tfObj.PrivateKeyAttributes.Algorithm.ValueString()),
					CryptoProviders:  cryptoProviders,
					KeySpec:          awstypes.KeySpec(tfObj.PrivateKeyAttributes.KeySpec.ValueString()),
					KeyUsageProperty: expandKeyUsageProperty(tfObj.PrivateKeyAttributes.KeyUsageProperty),
					MinimalKeyLength: minimalKeyLength,
				},
				PrivateKeyFlags: &awstypes.PrivateKeyFlagsV4{
					ClientVersion:                      awstypes.ClientCompatibilityV4(tfObj.PrivateKeyFlags.ClientVersion.ValueString()),
					ExportableKey:                      tfObj.PrivateKeyFlags.ExportableKey.ValueBoolPointer(),
					RequireAlternateSignatureAlgorithm: tfObj.PrivateKeyFlags.RequireAlternateSignatureAlgorithm.ValueBoolPointer(),
					RequireSameKeyRenewal:              tfObj.PrivateKeyFlags.RequireSameKeyRenewal.ValueBoolPointer(),
					StrongKeyProtectionRequired:        tfObj.PrivateKeyFlags.StrongKeyProtectionRequired.ValueBoolPointer(),
					UseLegacyProvider:                  tfObj.PrivateKeyFlags.UseLegacyProvider.ValueBoolPointer(),
				},
				SubjectNameFlags: &awstypes.SubjectNameFlagsV4{
					RequireCommonName:       tfObj.SubjectNameFlags.RequireCommonName.ValueBoolPointer(),
					RequireDirectoryPath:    tfObj.SubjectNameFlags.RequireDirectoryPath.ValueBoolPointer(),
					RequireDnsAsCn:          tfObj.SubjectNameFlags.RequireDnsAsCn.ValueBoolPointer(),
					RequireEmail:            tfObj.SubjectNameFlags.RequireEmail.ValueBoolPointer(),
					SanRequireDirectoryGuid: tfObj.SubjectNameFlags.SanRequireDirectoryGuid.ValueBoolPointer(),
					SanRequireDns:           tfObj.SubjectNameFlags.SanRequireDns.ValueBoolPointer(),
					SanRequireDomainDns:     tfObj.SubjectNameFlags.SanRequireDomainDns.ValueBoolPointer(),
					SanRequireEmail:         tfObj.SubjectNameFlags.SanRequireEmail.ValueBoolPointer(),
					SanRequireSpn:           tfObj.SubjectNameFlags.SanRequireSpn.ValueBoolPointer(),
					SanRequireUpn:           tfObj.SubjectNameFlags.SanRequireUpn.ValueBoolPointer(),
				},
				SupersededTemplates: supersededTemplates,
			},
		}
		return apiObject, diags
	default:
		diags.AddError(fmt.Sprintf("Unsupported policy schema version %d", policySchema), "policySchema")
		return nil, diags
	}
}

// func expandDefinitionV3(ctx context.Context, tfObj definitionData) (*awstypes.TemplateDefinitionMemberTemplateV3, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	var cryptoProviders []string
// 	d := tfObj.PrivateKeyAttributes.CryptoProviders.ElementsAs(ctx, &cryptoProviders, false)
// 	diags.Append(d...)

// 	var policiesData []policiesData
// 	d = tfObj.Extensions.ApplicationPolicies.Policies.ElementsAs(ctx, &policiesData, false)
// 	diags.Append(d...)

// 	var minimalKeyLength *int32
// 	if !tfObj.PrivateKeyAttributes.MinimalKeyLength.IsNull() {
// 		minimalKeyLength = aws.Int32(int32(tfObj.PrivateKeyAttributes.MinimalKeyLength.ValueInt64()))
// 	}

// 	var supersededTemplates []string
// 	d = tfObj.SupersededTemplates.ElementsAs(ctx, &supersededTemplates, false)
// 	diags.Append(d...)

// 	apiObject := &awstypes.TemplateDefinitionMemberTemplateV3{
// 		Value: awstypes.TemplateV3{
// 			CertificateValidity: &awstypes.CertificateValidity{
// 				RenewalPeriod: &awstypes.ValidityPeriod{
// 					Period:     tfObj.CertificateValidity.RenewalPeriod.Period.ValueInt64Pointer(),
// 					PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.RenewalPeriod.PeriodType.ValueString()),
// 				},
// 				ValidityPeriod: &awstypes.ValidityPeriod{
// 					Period:     tfObj.CertificateValidity.ValidityPeriod.Period.ValueInt64Pointer(),
// 					PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.ValidityPeriod.PeriodType.ValueString()),
// 				},
// 			},
// 			EnrollmentFlags: &awstypes.EnrollmentFlagsV3{
// 				EnableKeyReuseOnNtTokenKeysetStorageFull:  tfObj.EnrollmentFlags.EnableKeyReuseOnNtTokenKeysetStorageFull.ValueBoolPointer(),
// 				IncludeSymmetricAlgorithms:                tfObj.EnrollmentFlags.IncludeSymmetricAlgorithms.ValueBoolPointer(),
// 				NoSecurityExtension:                       tfObj.EnrollmentFlags.NoSecurityExtension.ValueBoolPointer(),
// 				RemoveInvalidCertificateFromPersonalStore: tfObj.EnrollmentFlags.RemoveInvalidCertificateFromPersonalStore.ValueBoolPointer(),
// 				UserInteractionRequired:                   tfObj.EnrollmentFlags.UserInteractionRequired.ValueBoolPointer(),
// 			},
// 			Extensions: &awstypes.ExtensionsV3{
// 				KeyUsage: &awstypes.KeyUsage{
// 					Critical: tfObj.Extensions.KeyUsage.Critical.ValueBoolPointer(),
// 					UsageFlags: &awstypes.KeyUsageFlags{
// 						DataEncipherment: tfObj.Extensions.KeyUsage.UsageFlags.DataEncipherment.ValueBoolPointer(),
// 						DigitalSignature: tfObj.Extensions.KeyUsage.UsageFlags.DigitalSignature.ValueBoolPointer(),
// 						KeyAgreement:     tfObj.Extensions.KeyUsage.UsageFlags.KeyAgreement.ValueBoolPointer(),
// 						KeyEncipherment:  tfObj.Extensions.KeyUsage.UsageFlags.KeyEncipherment.ValueBoolPointer(),
// 						NonRepudiation:   tfObj.Extensions.KeyUsage.UsageFlags.NonRepudiation.ValueBoolPointer(),
// 					},
// 				},
// 				ApplicationPolicies: &awstypes.ApplicationPolicies{
// 					Critical: tfObj.Extensions.ApplicationPolicies.Critical.ValueBoolPointer(),
// 					Policies: expandPolicies(policiesData),
// 				},
// 			},
// 			GeneralFlags: &awstypes.GeneralFlagsV3{
// 				AutoEnrollment: tfObj.GeneralFlags.AutoEnrollment.ValueBoolPointer(),
// 				MachineType:    tfObj.GeneralFlags.MachineType.ValueBoolPointer(),
// 			},
// 			HashAlgorithm: awstypes.HashAlgorithm(tfObj.HashAlgorithm.ValueString()),
// 			PrivateKeyAttributes: &awstypes.PrivateKeyAttributesV3{
// 				Algorithm:        awstypes.PrivateKeyAlgorithm(tfObj.PrivateKeyAttributes.Algorithm.ValueString()),
// 				CryptoProviders:  cryptoProviders,
// 				KeySpec:          awstypes.KeySpec(tfObj.PrivateKeyAttributes.KeySpec.ValueString()),
// 				KeyUsageProperty: expandKeyUsageProperty(tfObj.PrivateKeyAttributes.KeyUsageProperty),
// 				MinimalKeyLength: minimalKeyLength,
// 			},
// 			PrivateKeyFlags: &awstypes.PrivateKeyFlagsV3{
// 				ClientVersion:                      awstypes.ClientCompatibilityV3(tfObj.PrivateKeyFlags.ClientVersion.ValueString()),
// 				ExportableKey:                      tfObj.PrivateKeyFlags.ExportableKey.ValueBoolPointer(),
// 				RequireAlternateSignatureAlgorithm: tfObj.PrivateKeyFlags.RequireAlternateSignatureAlgorithm.ValueBoolPointer(),
// 				StrongKeyProtectionRequired:        tfObj.PrivateKeyFlags.StrongKeyProtectionRequired.ValueBoolPointer(),
// 			},
// 			SubjectNameFlags: &awstypes.SubjectNameFlagsV3{
// 				RequireCommonName:       tfObj.SubjectNameFlags.RequireCommonName.ValueBoolPointer(),
// 				RequireDirectoryPath:    tfObj.SubjectNameFlags.RequireDirectoryPath.ValueBoolPointer(),
// 				RequireDnsAsCn:          tfObj.SubjectNameFlags.RequireDnsAsCn.ValueBoolPointer(),
// 				RequireEmail:            tfObj.SubjectNameFlags.RequireEmail.ValueBoolPointer(),
// 				SanRequireDirectoryGuid: tfObj.SubjectNameFlags.SanRequireDirectoryGuid.ValueBoolPointer(),
// 				SanRequireDns:           tfObj.SubjectNameFlags.SanRequireDns.ValueBoolPointer(),
// 				SanRequireDomainDns:     tfObj.SubjectNameFlags.SanRequireDomainDns.ValueBoolPointer(),
// 				SanRequireEmail:         tfObj.SubjectNameFlags.SanRequireEmail.ValueBoolPointer(),
// 				SanRequireSpn:           tfObj.SubjectNameFlags.SanRequireSpn.ValueBoolPointer(),
// 				SanRequireUpn:           tfObj.SubjectNameFlags.SanRequireUpn.ValueBoolPointer(),
// 			},
// 			SupersededTemplates: supersededTemplates,
// 		},
// 	}

// 	return apiObject, diags
// }

// func expandDefinitionV4(ctx context.Context, tfObj definitionData) (*awstypes.TemplateDefinitionMemberTemplateV4, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	var cryptoProviders []string
// 	d := tfObj.PrivateKeyAttributes.CryptoProviders.ElementsAs(ctx, &cryptoProviders, false)
// 	diags.Append(d...)

// 	var policiesData []policiesData
// 	d = tfObj.Extensions.ApplicationPolicies.Policies.ElementsAs(ctx, &policiesData, false)
// 	diags.Append(d...)

// 	var minimalKeyLength *int32
// 	if !tfObj.PrivateKeyAttributes.MinimalKeyLength.IsNull() {
// 		minimalKeyLength = aws.Int32(int32(tfObj.PrivateKeyAttributes.MinimalKeyLength.ValueInt64()))
// 	}

// 	var supersededTemplates []string
// 	d = tfObj.SupersededTemplates.ElementsAs(ctx, &supersededTemplates, false)
// 	diags.Append(d...)

// 	apiObject := &awstypes.TemplateDefinitionMemberTemplateV4{
// 		Value: awstypes.TemplateV4{
// 			CertificateValidity: &awstypes.CertificateValidity{
// 				RenewalPeriod: &awstypes.ValidityPeriod{
// 					Period:     tfObj.CertificateValidity.RenewalPeriod.Period.ValueInt64Pointer(),
// 					PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.RenewalPeriod.PeriodType.ValueString()),
// 				},
// 				ValidityPeriod: &awstypes.ValidityPeriod{
// 					Period:     tfObj.CertificateValidity.ValidityPeriod.Period.ValueInt64Pointer(),
// 					PeriodType: awstypes.ValidityPeriodType(tfObj.CertificateValidity.ValidityPeriod.PeriodType.ValueString()),
// 				},
// 			},
// 			EnrollmentFlags: &awstypes.EnrollmentFlagsV4{
// 				EnableKeyReuseOnNtTokenKeysetStorageFull:  tfObj.EnrollmentFlags.EnableKeyReuseOnNtTokenKeysetStorageFull.ValueBoolPointer(),
// 				IncludeSymmetricAlgorithms:                tfObj.EnrollmentFlags.IncludeSymmetricAlgorithms.ValueBoolPointer(),
// 				NoSecurityExtension:                       tfObj.EnrollmentFlags.NoSecurityExtension.ValueBoolPointer(),
// 				RemoveInvalidCertificateFromPersonalStore: tfObj.EnrollmentFlags.RemoveInvalidCertificateFromPersonalStore.ValueBoolPointer(),
// 				UserInteractionRequired:                   tfObj.EnrollmentFlags.UserInteractionRequired.ValueBoolPointer(),
// 			},
// 			Extensions: &awstypes.ExtensionsV4{
// 				KeyUsage: &awstypes.KeyUsage{
// 					Critical: tfObj.Extensions.KeyUsage.Critical.ValueBoolPointer(),
// 					UsageFlags: &awstypes.KeyUsageFlags{
// 						DataEncipherment: tfObj.Extensions.KeyUsage.UsageFlags.DataEncipherment.ValueBoolPointer(),
// 						DigitalSignature: tfObj.Extensions.KeyUsage.UsageFlags.DigitalSignature.ValueBoolPointer(),
// 						KeyAgreement:     tfObj.Extensions.KeyUsage.UsageFlags.KeyAgreement.ValueBoolPointer(),
// 						KeyEncipherment:  tfObj.Extensions.KeyUsage.UsageFlags.KeyEncipherment.ValueBoolPointer(),
// 						NonRepudiation:   tfObj.Extensions.KeyUsage.UsageFlags.NonRepudiation.ValueBoolPointer(),
// 					},
// 				},
// 				ApplicationPolicies: &awstypes.ApplicationPolicies{
// 					Critical: tfObj.Extensions.ApplicationPolicies.Critical.ValueBoolPointer(),
// 					Policies: expandPolicies(policiesData),
// 				},
// 			},
// 			GeneralFlags: &awstypes.GeneralFlagsV4{
// 				AutoEnrollment: tfObj.GeneralFlags.AutoEnrollment.ValueBoolPointer(),
// 				MachineType:    tfObj.GeneralFlags.MachineType.ValueBoolPointer(),
// 			},
// 			HashAlgorithm: awstypes.HashAlgorithm(tfObj.HashAlgorithm.ValueString()),
// 			PrivateKeyAttributes: &awstypes.PrivateKeyAttributesV4{
// 				Algorithm:        awstypes.PrivateKeyAlgorithm(tfObj.PrivateKeyAttributes.Algorithm.ValueString()),
// 				CryptoProviders:  cryptoProviders,
// 				KeySpec:          awstypes.KeySpec(tfObj.PrivateKeyAttributes.KeySpec.ValueString()),
// 				KeyUsageProperty: expandKeyUsageProperty(tfObj.PrivateKeyAttributes.KeyUsageProperty),
// 				MinimalKeyLength: minimalKeyLength,
// 			},
// 			PrivateKeyFlags: &awstypes.PrivateKeyFlagsV4{
// 				ClientVersion:                      awstypes.ClientCompatibilityV4(tfObj.PrivateKeyFlags.ClientVersion.ValueString()),
// 				ExportableKey:                      tfObj.PrivateKeyFlags.ExportableKey.ValueBoolPointer(),
// 				RequireAlternateSignatureAlgorithm: tfObj.PrivateKeyFlags.RequireAlternateSignatureAlgorithm.ValueBoolPointer(),
// 				RequireSameKeyRenewal:              tfObj.PrivateKeyFlags.RequireSameKeyRenewal.ValueBoolPointer(),
// 				StrongKeyProtectionRequired:        tfObj.PrivateKeyFlags.StrongKeyProtectionRequired.ValueBoolPointer(),
// 				UseLegacyProvider:                  tfObj.PrivateKeyFlags.UseLegacyProvider.ValueBoolPointer(),
// 			},
// 			SubjectNameFlags: &awstypes.SubjectNameFlagsV4{
// 				RequireCommonName:       tfObj.SubjectNameFlags.RequireCommonName.ValueBoolPointer(),
// 				RequireDirectoryPath:    tfObj.SubjectNameFlags.RequireDirectoryPath.ValueBoolPointer(),
// 				RequireDnsAsCn:          tfObj.SubjectNameFlags.RequireDnsAsCn.ValueBoolPointer(),
// 				RequireEmail:            tfObj.SubjectNameFlags.RequireEmail.ValueBoolPointer(),
// 				SanRequireDirectoryGuid: tfObj.SubjectNameFlags.SanRequireDirectoryGuid.ValueBoolPointer(),
// 				SanRequireDns:           tfObj.SubjectNameFlags.SanRequireDns.ValueBoolPointer(),
// 				SanRequireDomainDns:     tfObj.SubjectNameFlags.SanRequireDomainDns.ValueBoolPointer(),
// 				SanRequireEmail:         tfObj.SubjectNameFlags.SanRequireEmail.ValueBoolPointer(),
// 				SanRequireSpn:           tfObj.SubjectNameFlags.SanRequireSpn.ValueBoolPointer(),
// 				SanRequireUpn:           tfObj.SubjectNameFlags.SanRequireUpn.ValueBoolPointer(),
// 			},
// 			SupersededTemplates: supersededTemplates,
// 		},
// 	}

// 	return apiObject, diags
// }

func flattenDefinition(ctx context.Context, apiObject awstypes.TemplateDefinition) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	switch v := apiObject.(type) {
	case *awstypes.TemplateDefinitionMemberTemplateV2:
		certificateValidityValue, d := flattenCertificateValidity(ctx, v.Value.CertificateValidity)
		diags.Append(d...)

		enrollmentFlagsValue, d := flattenEnrollmentFlags(ctx, v.Value.EnrollmentFlags)
		diags.Append(d...)

		extensions, d := flattenExtensions(ctx, v.Value.Extensions)
		diags.Append(d...)

		generalFlags, d := flattenGeneralFlags(ctx, v.Value.GeneralFlags)
		diags.Append(d...)

		privateKeyAttributes, d := flattenPrivateKeyAttributes(ctx, v.Value.PrivateKeyAttributes)
		diags.Append(d...)

		privateKeyFlags, d := flattenPrivateKeyFlags(ctx, v.Value.PrivateKeyFlags)
		diags.Append(d...)

		subjectNameFlags, d := flattenSubjectNameFlags(ctx, v.Value.SubjectNameFlags)
		diags.Append(d...)

		obj := map[string]attr.Value{
			"certificate_validity":   certificateValidityValue,
			"enrollment_flags":       enrollmentFlagsValue,
			"extensions":             extensions,
			"general_flags":          generalFlags,
			"private_key_attributes": privateKeyAttributes,
			"private_key_flags":      privateKeyFlags,
			"subject_name_flags":     subjectNameFlags,
			"superseded_templates":   flex.FlattenFrameworkStringValueSet(ctx, v.Value.SupersededTemplates),
		}

		objVal, d := types.ObjectValue(definitionAttrTypes, obj)
		diags.Append(d...)

		return objVal, diags
	case *awstypes.TemplateDefinitionMemberTemplateV3:
		certificateValidityValue, d := flattenCertificateValidity(ctx, v.Value.CertificateValidity)
		diags.Append(d...)

		enrollmentFlagsValue, d := flattenEnrollmentFlags(ctx, v.Value.EnrollmentFlags)
		diags.Append(d...)

		extensions, d := flattenExtensions(ctx, v.Value.Extensions)
		diags.Append(d...)

		generalFlags, d := flattenGeneralFlags(ctx, v.Value.GeneralFlags)
		diags.Append(d...)

		privateKeyAttributes, d := flattenPrivateKeyAttributes(ctx, v.Value.PrivateKeyAttributes)
		diags.Append(d...)

		privateKeyFlags, d := flattenPrivateKeyFlags(ctx, v.Value.PrivateKeyFlags)
		diags.Append(d...)

		subjectNameFlags, d := flattenSubjectNameFlags(ctx, v.Value.SubjectNameFlags)
		diags.Append(d...)

		obj := map[string]attr.Value{
			"certificate_validity":   certificateValidityValue,
			"enrollment_flags":       enrollmentFlagsValue,
			"extensions":             extensions,
			"general_flags":          generalFlags,
			"hash_algorithm":         flex.StringValueToFramework(ctx, string(v.Value.HashAlgorithm)),
			"private_key_attributes": privateKeyAttributes,
			"private_key_flags":      privateKeyFlags,
			"subject_name_flags":     subjectNameFlags,
			"superseded_templates":   flex.FlattenFrameworkStringValueSet(ctx, v.Value.SupersededTemplates),
		}

		objVal, d := types.ObjectValue(definitionAttrTypes, obj)
		diags.Append(d...)
		return objVal, diags
	case *awstypes.TemplateDefinitionMemberTemplateV4:
		certificateValidityValue, d := flattenCertificateValidity(ctx, v.Value.CertificateValidity)
		diags.Append(d...)

		enrollmentFlagsValue, d := flattenEnrollmentFlags(ctx, v.Value.EnrollmentFlags)
		diags.Append(d...)

		extensions, d := flattenExtensions(ctx, v.Value.Extensions)
		diags.Append(d...)

		generalFlags, d := flattenGeneralFlags(ctx, v.Value.GeneralFlags)
		diags.Append(d...)

		privateKeyAttributes, d := flattenPrivateKeyAttributes(ctx, v.Value.PrivateKeyAttributes)
		diags.Append(d...)

		privateKeyFlags, d := flattenPrivateKeyFlags(ctx, v.Value.PrivateKeyFlags)
		diags.Append(d...)

		subjectNameFlags, d := flattenSubjectNameFlags(ctx, v.Value.SubjectNameFlags)
		diags.Append(d...)

		obj := map[string]attr.Value{
			"certificate_validity":   certificateValidityValue,
			"enrollment_flags":       enrollmentFlagsValue,
			"extensions":             extensions,
			"general_flags":          generalFlags,
			"hash_algorithm":         flex.StringValueToFramework(ctx, string(v.Value.HashAlgorithm)),
			"private_key_attributes": privateKeyAttributes,
			"private_key_flags":      privateKeyFlags,
			"subject_name_flags":     subjectNameFlags,
			"superseded_templates":   flex.FlattenFrameworkStringValueSet(ctx, v.Value.SupersededTemplates),
		}

		objVal, d := types.ObjectValue(definitionAttrTypes, obj)
		diags.Append(d...)
		return objVal, diags
	default:
		diags.Append(diag.NewErrorDiagnostic("unknown template definition type", fmt.Sprintf("Type passed to flattenDefinition was %T", v)))
		objVal := types.ObjectNull(definitionAttrTypes)
		return objVal, diags
	}
}

// func flattenDefinitionV2(ctx context.Context, apiObject awstypes.TemplateV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	certificateValidityValue, d := flattenCertificateValidity(ctx, apiObject.CertificateValidity)
// 	diags.Append(d...)

// 	enrollmentFlagsValue, d := flattenEnrollmentFlagsV2(ctx, apiObject.EnrollmentFlags)
// 	diags.Append(d...)

// 	extensions, d := flattenExtensionsV2(ctx, apiObject.Extensions)
// 	diags.Append(d...)

// 	generalFlags, d := flattenGeneralFlagsV2(ctx, apiObject.GeneralFlags)
// 	diags.Append(d...)

// 	privateKeyAttributes, d := flattenPrivateKeyAttributesV2(ctx, apiObject.PrivateKeyAttributes)
// 	diags.Append(d...)

// 	privateKeyFlags, d := flattenPrivateKeyFlagsV2(ctx, apiObject.PrivateKeyFlags)
// 	diags.Append(d...)

// 	subjectNameFlags, d := flattenSubjectNameFlagsV2(ctx, apiObject.SubjectNameFlags)
// 	diags.Append(d...)

// 	obj := map[string]attr.Value{
// 		"certificate_validity":   certificateValidityValue,
// 		"enrollment_flags":       enrollmentFlagsValue,
// 		"extensions":             extensions,
// 		"general_flags":          generalFlags,
// 		"private_key_attributes": privateKeyAttributes,
// 		"private_key_flags":      privateKeyFlags,
// 		"subject_name_flags":     subjectNameFlags,
// 		"superseded_templates":   flex.FlattenFrameworkStringValueSet(ctx, apiObject.SupersededTemplates),
// 	}

// 	objVal, d := types.ObjectValue(definitionAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenDefinitionV3(ctx context.Context, apiObject awstypes.TemplateV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	certificateValidityValue, d := flattenCertificateValidity(ctx, apiObject.CertificateValidity)
// 	diags.Append(d...)

// 	enrollmentFlagsValue, d := flattenEnrollmentFlagsV3(ctx, apiObject.EnrollmentFlags)
// 	diags.Append(d...)

// 	extensions, d := flattenExtensionsV3(ctx, apiObject.Extensions)
// 	diags.Append(d...)

// 	generalFlags, d := flattenGeneralFlagsV3(ctx, apiObject.GeneralFlags)
// 	diags.Append(d...)

// 	privateKeyAttributes, d := flattenPrivateKeyAttributesV3(ctx, apiObject.PrivateKeyAttributes)
// 	diags.Append(d...)

// 	privateKeyFlags, d := flattenPrivateKeyFlagsV3(ctx, apiObject.PrivateKeyFlags)
// 	diags.Append(d...)

// 	subjectNameFlags, d := flattenSubjectNameFlagsV3(ctx, apiObject.SubjectNameFlags)
// 	diags.Append(d...)

// 	obj := map[string]attr.Value{
// 		"certificate_validity":   certificateValidityValue,
// 		"enrollment_flags":       enrollmentFlagsValue,
// 		"extensions":             extensions,
// 		"general_flags":          generalFlags,
// 		"hash_algorithm":         flex.StringValueToFramework(ctx, string(apiObject.HashAlgorithm)),
// 		"private_key_attributes": privateKeyAttributes,
// 		"private_key_flags":      privateKeyFlags,
// 		"subject_name_flags":     subjectNameFlags,
// 		"superseded_templates":   flex.FlattenFrameworkStringValueSet(ctx, apiObject.SupersededTemplates),
// 	}

// 	objVal, d := types.ObjectValue(definitionAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenValidityPeriod(ctx context.Context, apiObject *awstypes.ValidityPeriod) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(validityPeriodAttrTypes), diags
	}

	obj := map[string]attr.Value{
		"period":      flex.Int64ToFramework(ctx, apiObject.Period),
		"period_type": flex.StringValueToFramework(ctx, apiObject.PeriodType),
	}
	objVal, d := types.ObjectValue(validityPeriodAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func flattenCertificateValidity(ctx context.Context, apiObject *awstypes.CertificateValidity) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(certificateValidityAttrTypes), diags
	}

	renewalPeriod, d := flattenValidityPeriod(ctx, apiObject.RenewalPeriod)
	diags.Append(d...)

	validityPeriod, d := flattenValidityPeriod(ctx, apiObject.ValidityPeriod)
	diags.Append(d...)

	obj := map[string]attr.Value{
		"renewal_period":  renewalPeriod,
		"validity_period": validityPeriod,
	}
	objVal, d := types.ObjectValue(certificateValidityAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func flattenEnrollmentFlags(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(enrollmentFlagsAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.EnrollmentFlagsV2:
		if v != nil {
			obj := map[string]attr.Value{
				"enable_key_reuse_on_nt_token_keyset_storage_full": flex.BoolToFramework(ctx, v.EnableKeyReuseOnNtTokenKeysetStorageFull),
				"include_symmetric_algorithms":                     flex.BoolToFramework(ctx, v.IncludeSymmetricAlgorithms),
				"no_security_extension":                            flex.BoolToFramework(ctx, v.NoSecurityExtension),
				"remove_invalid_certificate_from_personal_store":   flex.BoolToFramework(ctx, v.RemoveInvalidCertificateFromPersonalStore),
				"user_interaction_required":                        flex.BoolToFramework(ctx, v.UserInteractionRequired),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(enrollmentFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.EnrollmentFlagsV3:
		if v != nil {
			obj := map[string]attr.Value{
				"enable_key_reuse_on_nt_token_keyset_storage_full": flex.BoolToFramework(ctx, v.EnableKeyReuseOnNtTokenKeysetStorageFull),
				"include_symmetric_algorithms":                     flex.BoolToFramework(ctx, v.IncludeSymmetricAlgorithms),
				"no_security_extension":                            flex.BoolToFramework(ctx, v.NoSecurityExtension),
				"remove_invalid_certificate_from_personal_store":   flex.BoolToFramework(ctx, v.RemoveInvalidCertificateFromPersonalStore),
				"user_interaction_required":                        flex.BoolToFramework(ctx, v.UserInteractionRequired),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(enrollmentFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.EnrollmentFlagsV4:
		if v != nil {
			obj := map[string]attr.Value{
				"enable_key_reuse_on_nt_token_keyset_storage_full": flex.BoolToFramework(ctx, v.EnableKeyReuseOnNtTokenKeysetStorageFull),
				"include_symmetric_algorithms":                     flex.BoolToFramework(ctx, v.IncludeSymmetricAlgorithms),
				"no_security_extension":                            flex.BoolToFramework(ctx, v.NoSecurityExtension),
				"remove_invalid_certificate_from_personal_store":   flex.BoolToFramework(ctx, v.RemoveInvalidCertificateFromPersonalStore),
				"user_interaction_required":                        flex.BoolToFramework(ctx, v.UserInteractionRequired),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(enrollmentFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("Unknown type encoutered flattening", fmt.Sprintf("The type passed to flattenEnrollmentFlags was %T", v))
	}

	return objVal, diags
}

func flattenExtensions(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(extensionsAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.ExtensionsV2:
		if v != nil {
			keyUsage, d := flattenKeyUsage(ctx, v.KeyUsage)
			diags.Append(d...)

			applicationPolicies, d := flattenApplicationPolicies(ctx, v.ApplicationPolicies)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"key_usage":            keyUsage,
				"application_policies": applicationPolicies,
			}
			objVal, d = types.ObjectValue(extensionsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.ExtensionsV3:
		if v != nil {
			keyUsage, d := flattenKeyUsage(ctx, v.KeyUsage)
			diags.Append(d...)

			applicationPolicies, d := flattenApplicationPolicies(ctx, v.ApplicationPolicies)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"key_usage":            keyUsage,
				"application_policies": applicationPolicies,
			}
			objVal, d = types.ObjectValue(extensionsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.ExtensionsV4:
		if v != nil {
			keyUsage, d := flattenKeyUsage(ctx, v.KeyUsage)
			diags.Append(d...)

			applicationPolicies, d := flattenApplicationPolicies(ctx, v.ApplicationPolicies)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"key_usage":            keyUsage,
				"application_policies": applicationPolicies,
			}
			objVal, d = types.ObjectValue(extensionsAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("Unknown type encoutered flattening", fmt.Sprintf("The type passed to flattenExtensions was %T", v))
	}
	return objVal, diags
}

// func flattenExtensionsV2(ctx context.Context, apiObject *awstypes.ExtensionsV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(extensionsAttrTypes), diags
// 	}

// 	keyUsage, d := flattenKeyUsage(ctx, apiObject.KeyUsage)
// 	diags.Append(d...)

// 	applicationPolicies, d := flattenApplicationPolicies(ctx, apiObject.ApplicationPolicies)
// 	diags.Append(d...)

// 	obj := map[string]attr.Value{
// 		"key_usage":            keyUsage,
// 		"application_policies": applicationPolicies,
// 	}
// 	objVal, d := types.ObjectValue(extensionsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenExtensionsV3(ctx context.Context, apiObject *awstypes.ExtensionsV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(extensionsAttrTypes), diags
// 	}

// }

// func flattenExtensionsV4(ctx context.Context, apiObject *awstypes.ExtensionsV4) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(extensionsAttrTypes), diags
// 	}

// 	keyUsage, d := flattenKeyUsage(ctx, apiObject.KeyUsage)
// 	diags.Append(d...)

// 	applicationPolicies, d := flattenApplicationPolicies(ctx, apiObject.ApplicationPolicies)
// 	diags.Append(d...)

// 	obj := map[string]attr.Value{
// 		"key_usage":            keyUsage,
// 		"application_policies": applicationPolicies,
// 	}
// 	objVal, d := types.ObjectValue(extensionsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenKeyUsage(ctx context.Context, apiObject *awstypes.KeyUsage) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(keyUsageAttrTypes), diags
	}

	usageFlags, d := flattenUsageFlags(ctx, apiObject.UsageFlags)
	diags.Append(d...)

	obj := map[string]attr.Value{
		"critical":    flex.BoolToFramework(ctx, apiObject.Critical),
		"usage_flags": usageFlags,
	}
	objVal, d := types.ObjectValue(keyUsageAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func flattenUsageFlags(ctx context.Context, apiObject *awstypes.KeyUsageFlags) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(usageFlagsAttrTypes), diags
	}

	obj := map[string]attr.Value{
		"data_encipherment": flex.BoolToFramework(ctx, apiObject.DataEncipherment),
		"digital_signature": flex.BoolToFramework(ctx, apiObject.DigitalSignature),
		"key_agreement":     flex.BoolToFramework(ctx, apiObject.KeyAgreement),
		"key_encipherment":  flex.BoolToFramework(ctx, apiObject.KeyEncipherment),
		"non_repudiation":   flex.BoolToFramework(ctx, apiObject.NonRepudiation),
	}
	objVal, d := types.ObjectValue(usageFlagsAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func flattenApplicationPolicies(ctx context.Context, apiObject *awstypes.ApplicationPolicies) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(applicationPoliciesAttrTypes), diags
	}

	policies, d := flattenPolicies(ctx, apiObject.Policies)
	diags.Append(d...)

	obj := map[string]attr.Value{
		"policies": policies,
		"critical": flex.BoolToFramework(ctx, apiObject.Critical),
	}
	objVal, d := types.ObjectValue(applicationPoliciesAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func flattenPolicies(ctx context.Context, apiObject []awstypes.ApplicationPolicy) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	elements := []attr.Value{}

	for _, pol := range apiObject {
		switch v := pol.(type) {
		case *awstypes.ApplicationPolicyMemberPolicyObjectIdentifier:
			policy := map[string]attr.Value{
				"policy_object_identifier": flex.StringValueToFramework(ctx, v.Value),
				"policy_type": 		    	types.StringNull(),
			}
			policyObj, d := types.ObjectValue(policiesAttrTypes, policy)
			diags.Append(d...)
			elements = append(elements, policyObj)
		case *awstypes.ApplicationPolicyMemberPolicyType:
			policy := map[string]attr.Value{
				"policy_object_identifier": types.StringNull(),
				"policy_type":              flex.StringValueToFramework(ctx, v.Value),
			}
			policyObj, d := types.ObjectValue(policiesAttrTypes, policy)
			diags.Append(d...)
			elements = append(elements, policyObj)
		}
	}


	policiesVal, d := types.SetValue(basetypes.ObjectType{AttrTypes: policiesAttrTypes}, elements)
	diags.Append(d...)

	return policiesVal, diags
}

func flattenGeneralFlags(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(generalFlagsAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.GeneralFlagsV2:
		if v != nil {
			obj := map[string]attr.Value{
				"auto_enrollment": flex.BoolToFramework(ctx, v.AutoEnrollment),
				"machine_type":    flex.BoolToFramework(ctx, v.MachineType),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(generalFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.GeneralFlagsV3:
		if v != nil {

			obj := map[string]attr.Value{
				"auto_enrollment": flex.BoolToFramework(ctx, v.AutoEnrollment),
				"machine_type":    flex.BoolToFramework(ctx, v.MachineType),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(generalFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.GeneralFlagsV4:
		if v != nil {
			obj := map[string]attr.Value{
				"auto_enrollment": flex.BoolToFramework(ctx, v.AutoEnrollment),
				"machine_type":    flex.BoolToFramework(ctx, v.MachineType),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(generalFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("Unknown type encoutered flattening", fmt.Sprintf("The type passed to flattenGeneralFlags was %T", v))
	}
	return objVal, diags
}

// func flattenGeneralFlagsV2(ctx context.Context, apiObject *awstypes.GeneralFlagsV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(generalFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"auto_enrollment": flex.BoolToFramework(ctx, apiObject.AutoEnrollment),
// 		"machine_type":    flex.BoolToFramework(ctx, apiObject.MachineType),
// 	}
// 	objVal, d := types.ObjectValue(generalFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenGeneralFlagsV3(ctx context.Context, apiObject *awstypes.GeneralFlagsV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(generalFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"auto_enrollment": flex.BoolToFramework(ctx, apiObject.AutoEnrollment),
// 		"machine_type":    flex.BoolToFramework(ctx, apiObject.MachineType),
// 	}
// 	objVal, d := types.ObjectValue(generalFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenGeneralFlagsV4(ctx context.Context, apiObject *awstypes.GeneralFlagsV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(generalFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"auto_enrollment": flex.BoolToFramework(ctx, apiObject.AutoEnrollment),
// 		"machine_type":    flex.BoolToFramework(ctx, apiObject.MachineType),
// 	}
// 	objVal, d := types.ObjectValue(generalFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenPrivateKeyAttributes(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(privateKeyAttributesAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.PrivateKeyAttributesV2:
		if v != nil {
			obj := map[string]attr.Value{
				"crypto_providers":   flex.FlattenFrameworkStringValueSet(ctx, v.CryptoProviders),
				"key_spec":           flex.StringValueToFramework(ctx, string(v.KeySpec)),
				"minimal_key_length": flex.Int32ToFramework(ctx, v.MinimalKeyLength),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(privateKeyAttributesAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.PrivateKeyAttributesV3:
		if v != nil {
			keyUsageProp, d := flattenKeyUsageProperty(ctx, v.KeyUsageProperty)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"algorithm":          flex.StringValueToFramework(ctx, string(v.Algorithm)),
				"crypto_providers":   flex.FlattenFrameworkStringValueSet(ctx, v.CryptoProviders),
				"key_spec":           flex.StringValueToFramework(ctx, string(v.KeySpec)),
				"key_usage_property": keyUsageProp,
				"minimal_key_length": flex.Int32ToFramework(ctx, v.MinimalKeyLength),
			}
			objVal, d = types.ObjectValue(privateKeyAttributesAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.PrivateKeyAttributesV4:
		if v != nil {
			keyUsageProp, d := flattenKeyUsageProperty(ctx, v.KeyUsageProperty)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"algorithm":          flex.StringValueToFramework(ctx, string(v.Algorithm)),
				"crypto_providers":   flex.FlattenFrameworkStringValueSet(ctx, v.CryptoProviders),
				"key_spec":           flex.StringValueToFramework(ctx, string(v.KeySpec)),
				"key_usage_property": keyUsageProp,
				"minimal_key_length": flex.Int32ToFramework(ctx, v.MinimalKeyLength),
			}
			objVal, d = types.ObjectValue(privateKeyAttributesAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("Unknown type encoutered flattening", fmt.Sprintf("The type passed to flattenGeneralFlags was %T", v))
	}
	return objVal, diags
}

// func flattenPrivateKeyAttributesV2(ctx context.Context, apiObject *awstypes.PrivateKeyAttributesV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(privateKeyAttributesAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"key_spec":           flex.StringValueToFramework(ctx, string(apiObject.KeySpec)),
// 		"minimal_key_length": flex.Int32ToFramework(ctx, apiObject.MinimalKeyLength),
// 		"crypto_providers":   flex.FlattenFrameworkStringValueSet(ctx, apiObject.CryptoProviders),
// 	}
// 	objVal, d := types.ObjectValue(privateKeyAttributesAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenKeyUsageProperty(ctx context.Context, i awstypes.KeyUsageProperty) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(keyUsagePropertyAttrTypes)

	switch v := i.(type) {
	case *awstypes.KeyUsagePropertyMemberPropertyFlags:
		if v != nil {
			flagVal := map[string]attr.Value{
				"decrypt":       flex.BoolToFramework(ctx, v.Value.Decrypt),
				"key_agreement": flex.BoolToFramework(ctx, v.Value.KeyAgreement),
				"sign":          flex.BoolToFramework(ctx, v.Value.Sign),
			}
			flagObj, d := types.ObjectValue(keyUsagePropertyFlagsAttrTypes, flagVal)
			diags.Append(d...)

			obj := map[string]attr.Value{
				"property_flags": flagObj,
			}
			objVal, d = types.ObjectValue(keyUsagePropertyAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.KeyUsagePropertyMemberPropertyType:
		if v != nil {
			obj := map[string]attr.Value{
				"property_type": flex.StringValueToFramework(ctx, v.Value),
				"property_flags": types.ObjectNull(keyUsagePropertyFlagsAttrTypes),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(keyUsagePropertyAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("flattenKeyUsageProperty error", fmt.Sprintf("Unknown type passed, %T", v))
	}
	return objVal, diags
}

// func flattenPrivateKeyAttributesV3(ctx context.Context, apiObject *awstypes.PrivateKeyAttributesV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(privateKeyAttributesAttrTypes), diags
// 	}

// 	keyUsageProperty, d := flattenKeyUsageProperty(ctx, apiObject.KeyUsageProperty)
// 	diags.Append(d...)

// 	obj := map[string]attr.Value{
// 		"algorithm":          flex.StringValueToFramework(ctx, string(apiObject.Algorithm)),
// 		"crypto_providers":   flex.FlattenFrameworkStringValueSet(ctx, apiObject.CryptoProviders),
// 		"key_spec":           flex.StringValueToFramework(ctx, string(apiObject.KeySpec)),
// 		"key_usage_property": keyUsageProperty,
// 		"minimal_key_length": flex.Int32ToFramework(ctx, apiObject.MinimalKeyLength),
// 	}
// 	objVal, d := types.ObjectValue(privateKeyAttributesAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenPrivateKeyFlags(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(privateKeyFlagsAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.PrivateKeyFlagsV2:
		if v != nil {
			obj := map[string]attr.Value{
				"client_version":                 flex.StringValueToFramework(ctx, string(v.ClientVersion)),
				"exportable_key":                 flex.BoolToFramework(ctx, v.ExportableKey),
				"strong_key_protection_required": flex.BoolToFramework(ctx, v.StrongKeyProtectionRequired),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(privateKeyFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.PrivateKeyFlagsV3:
		if v != nil {
			obj := map[string]attr.Value{
				"client_version":                        flex.StringValueToFramework(ctx, string(v.ClientVersion)),
				"exportable_key":                        flex.BoolToFramework(ctx, v.ExportableKey),
				"require_alternate_signature_algorithm": flex.BoolToFramework(ctx, v.RequireAlternateSignatureAlgorithm),
				"strong_key_protection_required":        flex.BoolToFramework(ctx, v.StrongKeyProtectionRequired),
				
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(privateKeyFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.PrivateKeyFlagsV4:
		if v != nil {
			obj := map[string]attr.Value{
				"client_version":                        flex.StringValueToFramework(ctx, string(v.ClientVersion)),
				"exportable_key":                        flex.BoolToFramework(ctx, v.ExportableKey),
				"require_alternate_signature_algorithm": flex.BoolToFramework(ctx, v.RequireAlternateSignatureAlgorithm),
				"require_same_key_renewal":              flex.BoolToFramework(ctx, v.RequireSameKeyRenewal),
				"strong_key_protection_required":        flex.BoolToFramework(ctx, v.StrongKeyProtectionRequired),
				"use_legacy_provider":                   flex.BoolToFramework(ctx, v.UseLegacyProvider),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(privateKeyFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("flattenPrivateKeyFlags error", fmt.Sprintf("Unknown type passed, %T", v))
	}
	return objVal, diags
}

// func flattenPrivateKeyFlagsV2(ctx context.Context, apiObject *awstypes.PrivateKeyFlagsV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(privateKeyFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"client_version":                 flex.StringValueToFramework(ctx, string(apiObject.ClientVersion)),
// 		"exportable_key":                 flex.BoolToFramework(ctx, apiObject.ExportableKey),
// 		"strong_key_protection_required": flex.BoolToFramework(ctx, apiObject.StrongKeyProtectionRequired),
// 	}
// 	objVal, d := types.ObjectValue(privateKeyFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenPrivateKeyFlagsV3(ctx context.Context, apiObject *awstypes.PrivateKeyFlagsV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(privateKeyFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"client_version":                        flex.StringValueToFramework(ctx, string(apiObject.ClientVersion)),
// 		"exportable_key":                        flex.BoolToFramework(ctx, apiObject.ExportableKey),
// 		"require_alternate_signature_algorithm": flex.BoolToFramework(ctx, apiObject.RequireAlternateSignatureAlgorithm),
// 		"strong_key_protection_required":        flex.BoolToFramework(ctx, apiObject.StrongKeyProtectionRequired),
// 	}
// 	objVal, d := types.ObjectValue(privateKeyFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenSubjectNameFlags(ctx context.Context, apiObject interface{}) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	objVal := types.ObjectNull(subjectNameFlagsAttrTypes)

	switch v := apiObject.(type) {
	case *awstypes.SubjectNameFlagsV2:
		if v != nil {
			obj := map[string]attr.Value{
				"require_common_name":        flex.BoolToFramework(ctx, v.RequireCommonName),
				"require_directory_path":     flex.BoolToFramework(ctx, v.RequireDirectoryPath),
				"require_dns_as_cn":          flex.BoolToFramework(ctx, v.RequireDnsAsCn),
				"require_email":              flex.BoolToFramework(ctx, v.RequireEmail),
				"san_require_directory_guid": flex.BoolToFramework(ctx, v.SanRequireDirectoryGuid),
				"san_require_dns":            flex.BoolToFramework(ctx, v.SanRequireDns),
				"san_require_domain_dns":     flex.BoolToFramework(ctx, v.SanRequireDomainDns),
				"san_require_email":          flex.BoolToFramework(ctx, v.SanRequireEmail),
				"san_require_spn":            flex.BoolToFramework(ctx, v.SanRequireSpn),
				"san_require_upn":            flex.BoolToFramework(ctx, v.SanRequireUpn),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(subjectNameFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.SubjectNameFlagsV3:
		if v != nil {
			obj := map[string]attr.Value{
				"require_common_name":        flex.BoolToFramework(ctx, v.RequireCommonName),
				"require_directory_path":     flex.BoolToFramework(ctx, v.RequireDirectoryPath),
				"require_dns_as_cn":          flex.BoolToFramework(ctx, v.RequireDnsAsCn),
				"require_email":              flex.BoolToFramework(ctx, v.RequireEmail),
				"san_require_directory_guid": flex.BoolToFramework(ctx, v.SanRequireDirectoryGuid),
				"san_require_dns":            flex.BoolToFramework(ctx, v.SanRequireDns),
				"san_require_domain_dns":     flex.BoolToFramework(ctx, v.SanRequireDomainDns),
				"san_require_email":          flex.BoolToFramework(ctx, v.SanRequireEmail),
				"san_require_spn":            flex.BoolToFramework(ctx, v.SanRequireSpn),
				"san_require_upn":            flex.BoolToFramework(ctx, v.SanRequireUpn),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(subjectNameFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	case *awstypes.SubjectNameFlagsV4:
		if v != nil {
			obj := map[string]attr.Value{
				"require_common_name":        flex.BoolToFramework(ctx, v.RequireCommonName),
				"require_directory_path":     flex.BoolToFramework(ctx, v.RequireDirectoryPath),
				"require_dns_as_cn":          flex.BoolToFramework(ctx, v.RequireDnsAsCn),
				"require_email":              flex.BoolToFramework(ctx, v.RequireEmail),
				"san_require_directory_guid": flex.BoolToFramework(ctx, v.SanRequireDirectoryGuid),
				"san_require_dns":            flex.BoolToFramework(ctx, v.SanRequireDns),
				"san_require_domain_dns":     flex.BoolToFramework(ctx, v.SanRequireDomainDns),
				"san_require_email":          flex.BoolToFramework(ctx, v.SanRequireEmail),
				"san_require_spn":            flex.BoolToFramework(ctx, v.SanRequireSpn),
				"san_require_upn":            flex.BoolToFramework(ctx, v.SanRequireUpn),
			}
			var d diag.Diagnostics
			objVal, d = types.ObjectValue(subjectNameFlagsAttrTypes, obj)
			diags.Append(d...)
		}
	default:
		diags.AddError("flattenSubjectNameFlags error", fmt.Sprintf("Unknown type passed, %T", v))
	}
	return objVal, diags
}

// func flattenSubjectNameFlagsV2(ctx context.Context, apiObject *awstypes.SubjectNameFlagsV2) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(subjectNameFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"require_common_name":        flex.BoolToFramework(ctx, apiObject.RequireCommonName),
// 		"require_directory_path":     flex.BoolToFramework(ctx, apiObject.RequireDirectoryPath),
// 		"require_dns_as_cn":          flex.BoolToFramework(ctx, apiObject.RequireDnsAsCn),
// 		"require_email":              flex.BoolToFramework(ctx, apiObject.RequireEmail),
// 		"san_require_directory_guid": flex.BoolToFramework(ctx, apiObject.SanRequireDirectoryGuid),
// 		"san_require_dns":            flex.BoolToFramework(ctx, apiObject.SanRequireDns),
// 		"san_require_domain_dns":     flex.BoolToFramework(ctx, apiObject.SanRequireDomainDns),
// 		"san_require_email":          flex.BoolToFramework(ctx, apiObject.SanRequireEmail),
// 		"san_require_spn":            flex.BoolToFramework(ctx, apiObject.SanRequireSpn),
// 		"san_require_upn":            flex.BoolToFramework(ctx, apiObject.SanRequireUpn),
// 	}
// 	objVal, d := types.ObjectValue(subjectNameFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

// func flattenSubjectNameFlagsV3(ctx context.Context, apiObject *awstypes.SubjectNameFlagsV3) (types.Object, diag.Diagnostics) {
// 	var diags diag.Diagnostics

// 	if apiObject == nil {
// 		return types.ObjectNull(subjectNameFlagsAttrTypes), diags
// 	}

// 	obj := map[string]attr.Value{
// 		"require_common_name":        flex.BoolToFramework(ctx, apiObject.RequireCommonName),
// 		"require_directory_path":     flex.BoolToFramework(ctx, apiObject.RequireDirectoryPath),
// 		"require_dns_as_cn":          flex.BoolToFramework(ctx, apiObject.RequireDnsAsCn),
// 		"require_email":              flex.BoolToFramework(ctx, apiObject.RequireEmail),
// 		"san_require_directory_guid": flex.BoolToFramework(ctx, apiObject.SanRequireDirectoryGuid),
// 		"san_require_dns":            flex.BoolToFramework(ctx, apiObject.SanRequireDns),
// 		"san_require_domain_dns":     flex.BoolToFramework(ctx, apiObject.SanRequireDomainDns),
// 		"san_require_email":          flex.BoolToFramework(ctx, apiObject.SanRequireEmail),
// 		"san_require_spn":            flex.BoolToFramework(ctx, apiObject.SanRequireSpn),
// 		"san_require_upn":            flex.BoolToFramework(ctx, apiObject.SanRequireUpn),
// 	}
// 	objVal, d := types.ObjectValue(subjectNameFlagsAttrTypes, obj)
// 	diags.Append(d...)

// 	return objVal, diags
// }

func flattenRevision(ctx context.Context, apiObject *awstypes.TemplateRevision) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return types.ObjectNull(revisionAttrTypes), diags
	}

	obj := map[string]attr.Value{
		"major_revision": flex.Int32ToFramework(ctx, apiObject.MajorRevision),
		"minor_revision": flex.Int32ToFramework(ctx, apiObject.MinorRevision),
	}
	objVal, d := types.ObjectValue(revisionAttrTypes, obj)
	diags.Append(d...)

	return objVal, diags
}

func hashAlgorithmStrings() []string {
	var s []string

	values := new(awstypes.HashAlgorithm).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func clientCompatibilityV3Strings() []string {
	var s []string

	values := new(awstypes.ClientCompatibilityV3).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func clientCompatibilityV4Strings() []string {
	var s []string

	values := new(awstypes.ClientCompatibilityV4).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func algorithmStrings() []string {
	var s []string

	values := new(awstypes.PrivateKeyAlgorithm).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func keyUsagePropertyTypeStrings() []string {
	var s []string

	values := new(awstypes.KeyUsagePropertyType).Values()

	for _, v := range values {
		s = append(s, string(v))
	}
	return s
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func validateClientVersion(ps int64, cv string) diag.Diagnostics {
	var diags diag.Diagnostics

	switch ps {
	case 2:
		if !stringInSlice(cv, clientCompatibilityV2Strings()) {
			diags.AddAttributeError(path.Root("client_version"), "Invalid client_version",
				fmt.Sprintf("client_version must be one of %s", strings.Join(clientCompatibilityV2Strings(), ", ")))
		}
	case 3:
		if !stringInSlice(cv, clientCompatibilityV3Strings()) {
			diags.AddAttributeError(path.Root("client_version"), "Invalid client_version",
				fmt.Sprintf("client_version must be one of %s", strings.Join(clientCompatibilityV3Strings(), ", ")))
		}
	case 4:
		if !stringInSlice(cv, clientCompatibilityV4Strings()) {
			diags.AddAttributeError(path.Root("client_version"), "Invalid client_version",
				fmt.Sprintf("client_version must be one of %s", strings.Join(clientCompatibilityV4Strings(), ", ")))
		}
	default:
		diags.AddError("client_version validation error", fmt.Sprintf("Invalid provider schema version %d", ps))
	}

	return diags
}
