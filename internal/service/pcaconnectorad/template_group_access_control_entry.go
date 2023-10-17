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
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// Function annotations are used for resource registration to the Provider. DO NOT EDIT.
// @FrameworkResource(name="Template Group Access Control Entry")
func newResourceTemplateGroupAccessControlEntry(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceTemplateGroupAccessControlEntry{}

	r.SetDefaultCreateTimeout(30 * time.Minute)
	r.SetDefaultUpdateTimeout(30 * time.Minute)
	r.SetDefaultDeleteTimeout(30 * time.Minute)

	return r, nil
}

const (
	ResNameTemplateGroupAccessControlEntry = "Template Group Access Control Entry"
)

type resourceTemplateGroupAccessControlEntry struct {
	framework.ResourceWithConfigure
	framework.WithTimeouts
}

func (r *resourceTemplateGroupAccessControlEntry) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_pcaconnectorad_template_group_access_control_entry"
}

func (r *resourceTemplateGroupAccessControlEntry) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"group_display_name": schema.StringAttribute{
				Required: true,

				Validators: []validator.String{
					stringvalidator.LengthAtLeast(0),
					stringvalidator.LengthAtMost(256),
					stringvalidator.RegexMatches(regexp.MustCompile(`^[\x20-\x7E]+$`), "must be a valid Active Directory group name"),
				},
			},
			"group_security_identifier": schema.StringAttribute{
				Required: true,

				Validators: []validator.String{
					stringvalidator.LengthAtLeast(7),
					stringvalidator.LengthAtMost(256),
					stringvalidator.RegexMatches(regexp.MustCompile(`^S-[0-9]-([0-9]+-){1,14}[0-9]+$`), "must be a valid Active Directory SID"),
				},

				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": framework.IDAttribute(),
			"template_arn": schema.StringAttribute{
				Required: true,

				Validators: []validator.String{
					stringvalidator.LengthAtLeast(5),
					stringvalidator.LengthAtMost(200),
					stringvalidator.RegexMatches(regexp.MustCompile(`^arn:[\w-]+:pca-connector-ad:[\w-]+:[0-9]+:connector\/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\/template\/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`), "must be a valid Template ARN"),
				},

				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"access_rights": schema.ListNestedBlock{
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"auto_enroll": schema.StringAttribute{
							Optional: true,

							Validators: []validator.String{
								stringvalidator.OneOf("ALLOW", "DENY"),
							},
						},
						"enroll": schema.StringAttribute{
							Optional: true,

							Validators: []validator.String{
								stringvalidator.OneOf("ALLOW", "DENY"),
							},
						},
					},
				},
			},
			// "timeouts": timeouts.Block(ctx, timeouts.Opts{
			// 	Create: true,
			// 	Update: true,
			// 	Delete: true,
			// }),
		},
	}
}

func (r *resourceTemplateGroupAccessControlEntry) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var plan resourceTemplateGroupAccessControlEntryData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.CreateTemplateGroupAccessControlEntryInput{
		// AccessRights: &awstypes.AccessRights{
		// 	Enroll: awstypes.AccessRight(plan.Enroll.ValueString()),
		// },
		GroupDisplayName:        aws.String(plan.GroupDisplayName.ValueString()),
		GroupSecurityIdentifier: aws.String(plan.GroupSecurityIdentifier.ValueString()),
		TemplateArn:             aws.String(plan.TemplateARN.ValueString()),
	}

	// if !plan.AutoEnroll.IsNull() {
	// 	in.AccessRights.AutoEnroll = awstypes.AccessRight(plan.Description.ValueString())
	// }

	if !plan.AccessRights.IsNull() {
		// TIP: Use an expander to assign a complex argument. The elements must be
		// deserialized into the appropriate struct before being passed to the expander.
		var tfList []accessRightsData
		resp.Diagnostics.Append(plan.AccessRights.ElementsAs(ctx, &tfList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		in.AccessRights = expandAccessRights(tfList)
	}

	out, err := conn.CreateTemplateGroupAccessControlEntry(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameTemplateGroupAccessControlEntry, plan.GroupDisplayName.String(), err),
			err.Error(),
		)
		return
	}
	if out == nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameTemplateGroupAccessControlEntry, plan.GroupDisplayName.String(), nil),
			errors.New("empty output").Error(),
		)
		return
	}

	id := plan.TemplateARN.ValueString() + "_" + plan.GroupSecurityIdentifier.ValueString()
	plan.ID = flex.StringToFramework(ctx, &id)

	// createTimeout := r.CreateTimeout(ctx, plan.Timeouts)
	// _, err = waitTemplateGroupAccessControlEntryCreated(ctx, conn, plan.ID.ValueString(), createTimeout)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForCreation, ResNameTemplateGroupAccessControlEntry, plan.GroupDisplayName.String(), err),
	// 		err.Error(),
	// 	)
	// 	return
	// }

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceTemplateGroupAccessControlEntry) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceTemplateGroupAccessControlEntryData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findTemplateGroupAccessControlEntryByID(ctx, conn, state.ID.ValueString())

	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionSetting, ResNameTemplateGroupAccessControlEntry, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	state.GroupDisplayName = flex.StringToFramework(ctx, out.GroupDisplayName)
	state.GroupSecurityIdentifier = flex.StringToFramework(ctx, out.GroupSecurityIdentifier)
	state.TemplateARN = flex.StringToFramework(ctx, out.TemplateArn)

	accessRights, d := flattenAccessRights(ctx, out.AccessRights)
	resp.Diagnostics.Append(d...)
	state.AccessRights = accessRights

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceTemplateGroupAccessControlEntry) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var plan, state resourceTemplateGroupAccessControlEntryData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.AccessRights.Equal(state.AccessRights) ||
		!plan.GroupDisplayName.Equal(state.GroupDisplayName) {

		in := &pcaconnectorad.UpdateTemplateGroupAccessControlEntryInput{
			GroupDisplayName: aws.String(plan.GroupDisplayName.ValueString()),
		}

		if !plan.AccessRights.IsNull() {
			var tfList []accessRightsData
			resp.Diagnostics.Append(plan.AccessRights.ElementsAs(ctx, &tfList, false)...)
			if resp.Diagnostics.HasError() {
				return
			}

			in.AccessRights = expandAccessRights(tfList)
		}

		out, err := conn.UpdateTemplateGroupAccessControlEntry(ctx, in)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionUpdating, ResNameTemplateGroupAccessControlEntry, plan.ID.String(), err),
				err.Error(),
			)
			return
		}
		if out == nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionUpdating, ResNameTemplateGroupAccessControlEntry, plan.ID.String(), nil),
				errors.New("empty output").Error(),
			)
			return
		}

	}

	// updateTimeout := r.UpdateTimeout(ctx, plan.Timeouts)
	// _, err := waitTemplateGroupAccessControlEntryUpdated(ctx, conn, plan.ID.ValueString(), updateTimeout)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForUpdate, ResNameTemplateGroupAccessControlEntry, plan.ID.String(), err),
	// 		err.Error(),
	// 	)
	// 	return
	// }

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceTemplateGroupAccessControlEntry) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceTemplateGroupAccessControlEntryData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.DeleteTemplateGroupAccessControlEntryInput{
		GroupSecurityIdentifier: aws.String(state.GroupSecurityIdentifier.ValueString()),
		TemplateArn:             aws.String(state.TemplateARN.ValueString()),
	}

	_, err := conn.DeleteTemplateGroupAccessControlEntry(ctx, in)
	if err != nil {
		var nfe *awstypes.ResourceNotFoundException
		if errors.As(err, &nfe) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionDeleting, ResNameTemplateGroupAccessControlEntry, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	// deleteTimeout := r.DeleteTimeout(ctx, state.Timeouts)
	// _, err = waitTemplateGroupAccessControlEntryDeleted(ctx, conn, state.ID.ValueString(), deleteTimeout)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForDeletion, ResNameTemplateGroupAccessControlEntry, state.ID.String(), err),
	// 		err.Error(),
	// 	)
	// 	return
	// }
}

func (r *resourceTemplateGroupAccessControlEntry) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// func waitTemplateGroupAccessControlEntryCreated(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*pcaconnectorad.TemplateGroupAccessControlEntry, error) {
// 	stateConf := &retry.StateChangeConf{
// 		Pending:                   []string{},
// 		Target:                    []string{statusNormal},
// 		Refresh:                   statusTemplateGroupAccessControlEntry(ctx, conn, id),
// 		Timeout:                   timeout,
// 		NotFoundChecks:            20,
// 		ContinuousTargetOccurence: 2,
// 	}

// 	outputRaw, err := stateConf.WaitForStateContext(ctx)
// 	if out, ok := outputRaw.(*pcaconnectorad.TemplateGroupAccessControlEntry); ok {
// 		return out, err
// 	}

// 	return nil, err
// }

// func waitTemplateGroupAccessControlEntryUpdated(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*pcaconnectorad.TemplateGroupAccessControlEntry, error) {
// 	stateConf := &retry.StateChangeConf{
// 		Pending:                   []string{statusChangePending},
// 		Target:                    []string{statusUpdated},
// 		Refresh:                   statusTemplateGroupAccessControlEntry(ctx, conn, id),
// 		Timeout:                   timeout,
// 		NotFoundChecks:            20,
// 		ContinuousTargetOccurence: 2,
// 	}

// 	outputRaw, err := stateConf.WaitForStateContext(ctx)
// 	if out, ok := outputRaw.(*pcaconnectorad.TemplateGroupAccessControlEntry); ok {
// 		return out, err
// 	}

// 	return nil, err
// }

// func waitTemplateGroupAccessControlEntryDeleted(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*pcaconnectorad.TemplateGroupAccessControlEntry, error) {
// 	stateConf := &retry.StateChangeConf{
// 		Pending: []string{statusDeleting, statusNormal},
// 		Target:  []string{},
// 		Refresh: statusTemplateGroupAccessControlEntry(ctx, conn, id),
// 		Timeout: timeout,
// 	}

// 	outputRaw, err := stateConf.WaitForStateContext(ctx)
// 	if out, ok := outputRaw.(*pcaconnectorad.TemplateGroupAccessControlEntry); ok {
// 		return out, err
// 	}

// 	return nil, err
// }

// func statusTemplateGroupAccessControlEntry(ctx context.Context, conn *pcaconnectorad.Client, id string) retry.StateRefreshFunc {
// 	return func() (interface{}, string, error) {
// 		out, err := findTemplateGroupAccessControlEntryByID(ctx, conn, id)
// 		if tfresource.NotFound(err) {
// 			return nil, "", nil
// 		}

// 		if err != nil {
// 			return nil, "", err
// 		}

// 		return out, aws.ToString(out.Status), nil
// 	}
// }

func findTemplateGroupAccessControlEntryByID(ctx context.Context, conn *pcaconnectorad.Client, id string) (*awstypes.AccessControlEntry, error) {
	idParts := strings.SplitN(id, "_", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		return nil, fmt.Errorf("unexpected format of ID (%q), expected <template_arn>_<group_security_identifier>", id)
	}

	arn := idParts[0]
	sid := idParts[1]

	in := &pcaconnectorad.GetTemplateGroupAccessControlEntryInput{
		GroupSecurityIdentifier: aws.String(sid),
		TemplateArn:             aws.String(arn),
	}

	out, err := conn.GetTemplateGroupAccessControlEntry(ctx, in)
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

	if out == nil || out.AccessControlEntry == nil {
		return nil, tfresource.NewEmptyResultError(in)
	}

	return out.AccessControlEntry, nil
}

func flattenAccessRights(ctx context.Context, apiObject *awstypes.AccessRights) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: accessRightsAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	obj := map[string]attr.Value{
		"auto_enroll": flex.StringValueToFramework(ctx, apiObject.AutoEnroll),
		"enroll":      flex.StringValueToFramework(ctx, apiObject.Enroll),
	}
	objVal, d := types.ObjectValue(accessRightsAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

// func flattenComplexArguments(ctx context.Context, apiObjects []*pcaconnectorad.ComplexArgument) (types.List, diag.Diagnostics) {
// 	var diags diag.Diagnostics
// 	elemType := types.ObjectType{AttrTypes: complexArgumentAttrTypes}

// 	if len(apiObjects) == 0 {
// 		return types.ListNull(elemType), diags
// 	}

// 	elems := []attr.Value{}
// 	for _, apiObject := range apiObjects {
// 		if apiObject == nil {
// 			continue
// 		}

// 		obj := map[string]attr.Value{
// 			"nested_required": flex.StringValueToFramework(ctx, apiObject.NestedRequired),
// 			"nested_optional": flex.StringValueToFramework(ctx, apiObject.NestedOptional),
// 		}
// 		objVal, d := types.ObjectValue(complexArgumentAttrTypes, obj)
// 		diags.Append(d...)

// 		elems = append(elems, objVal)
// 	}

// 	listVal, d := types.ListValue(elemType, elems)
// 	diags.Append(d...)

// 	return listVal, diags
// }

func expandAccessRights(tfList []accessRightsData) *awstypes.AccessRights {
	if len(tfList) == 0 {
		return nil
	}

	tfObj := tfList[0]
	apiObject := &awstypes.AccessRights{
		Enroll: awstypes.AccessRight(*tfObj.AutoEnroll.ValueStringPointer()),
	}
	if !tfObj.AutoEnroll.IsNull() {
		apiObject.AutoEnroll = awstypes.AccessRight(*tfObj.AutoEnroll.ValueStringPointer())
	}

	return apiObject
}

// func expandComplexArguments(tfList []complexArgumentData) []*pcaconnectorad.ComplexArgument {
// 	// TIP: The AWS API can be picky about whether you send a nil or zero-
// 	// length for an argument that should be cleared. For example, in some
// 	// cases, if you send a nil value, the AWS API interprets that as "make no
// 	// changes" when what you want to say is "remove everything." Sometimes
// 	// using a zero-length list will cause an error.
// 	//
// 	// As a result, here are two options. Usually, option 1, nil, will work as
// 	// expected, clearing the field. But, test going from something to nothing
// 	// to make sure it works. If not, try the second option.
// 	// TIP: Option 1: Returning nil for zero-length list
// 	if len(tfList) == 0 {
// 		return nil
// 	}

// 	var apiObject []*pcaconnectorad.ComplexArgument
// 	// TIP: Option 2: Return zero-length list for zero-length list. If option 1 does
// 	// not work, after testing going from something to nothing (if that is
// 	// possible), uncomment out the next line and remove option 1.
// 	//
// 	// apiObject := make([]*pcaconnectorad.ComplexArgument, 0)

// 	for _, tfObj := range tfList {
// 		item := &pcaconnectorad.ComplexArgument{
// 			NestedRequired: aws.String(tfObj.NestedRequired.ValueString()),
// 		}
// 		if !tfObj.NestedOptional.IsNull() {
// 			item.NestedOptional = aws.String(tfObj.NestedOptional.ValueString())
// 		}

// 		apiObject = append(apiObject, item)
// 	}

// 	return apiObject
// }

type resourceTemplateGroupAccessControlEntryData struct {
	AccessRights            types.List   `tfsdk:"access_rights"`
	ID                      types.String `tfsdk:"id"`
	GroupDisplayName        types.String `tfsdk:"group_display_name"`
	GroupSecurityIdentifier types.String `tfsdk:"group_security_identifier"`
	TemplateARN             types.String `tfsdk:"template_arn"`
	// Timeouts                timeouts.Value `tfsdk:"timeouts"`
}

type accessRightsData struct {
	AutoEnroll types.String `tfsdk:"auto_enroll"`
	Enroll     types.String `tfsdk:"enroll"`
}

var accessRightsAttrTypes = map[string]attr.Type{
	"auto_enroll": types.StringType,
	"enroll":      types.StringType,
}
