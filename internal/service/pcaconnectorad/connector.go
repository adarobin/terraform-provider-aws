// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pcaconnectorad

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pcaconnectorad"
	awstypes "github.com/aws/aws-sdk-go-v2/service/pcaconnectorad/types"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// Function annotations are used for resource registration to the Provider. DO NOT EDIT.
// @FrameworkResource(name="Connector")
// @Tags(identifierAttribute="arn")
func newResourceConnector(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceConnector{}

	r.SetDefaultCreateTimeout(30 * time.Minute)
	r.SetDefaultUpdateTimeout(30 * time.Minute)
	r.SetDefaultDeleteTimeout(30 * time.Minute)

	return r, nil
}

const (
	ResNameConnector = "Connector"
)

type resourceConnector struct {
	framework.ResourceWithConfigure
	framework.WithTimeouts
}

func (r *resourceConnector) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_pcaconnectorad_connector"
}

func (r *resourceConnector) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"arn": framework.ARNAttributeComputedOnly(),
			"certificate_authority_arn": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate_enrollment_policy_server_endpoint": schema.StringAttribute{
				Computed: true,
			},
			"directory_id": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id":              framework.IDAttribute(),
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
			"security_group_ids": schema.SetAttribute{
				Required:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *resourceConnector) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var plan resourceConnectorData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.CreateConnectorInput{
		CertificateAuthorityArn: aws.String(plan.CertificateAuthorityARN.ValueString()),
		DirectoryId:             aws.String(plan.DirectoryID.ValueString()),
		VpcInformation:          &awstypes.VpcInformation{},
		Tags:                    getTagsIn(ctx),
	}

	if !plan.SecurityGroupIDs.IsNull() {
		var sgList []string
		resp.Diagnostics.Append(plan.SecurityGroupIDs.ElementsAs(ctx, &sgList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		in.VpcInformation.SecurityGroupIds = sgList
	}

	out, err := conn.CreateConnector(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameConnector, plan.CertificateAuthorityARN.String(), err),
			err.Error(),
		)
		return
	}
	if out == nil || out.ConnectorArn == nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionCreating, ResNameConnector, plan.CertificateAuthorityARN.String(), nil),
			errors.New("empty output").Error(),
		)
		return
	}

	plan.ARN = flex.StringToFramework(ctx, out.ConnectorArn)
	plan.ID = flex.StringToFramework(ctx, out.ConnectorArn)

	createTimeout := r.CreateTimeout(ctx, plan.Timeouts)
	_, err = waitConnectorCreated(ctx, conn, plan.ID.ValueString(), createTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForCreation, ResNameConnector, plan.CertificateAuthorityARN.String(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceConnector) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceConnectorData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findConnectorByID(ctx, conn, state.ID.ValueString())

	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionSetting, ResNameConnector, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	state.ARN = flex.StringToFramework(ctx, out.Arn)
	state.CertificateAuthorityARN = flex.StringToFramework(ctx, out.CertificateAuthorityArn)
	state.CertificateEnrollmentPolicyServerEndpoint = flex.StringToFramework(ctx, out.CertificateEnrollmentPolicyServerEndpoint)
	state.DirectoryID = flex.StringToFramework(ctx, out.DirectoryId)
	state.ID = flex.StringToFramework(ctx, out.Arn)
	state.SecurityGroupIDs = flex.FlattenFrameworkStringValueSet(ctx, out.VpcInformation.SecurityGroupIds)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceConnector) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *resourceConnector) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().PCAConnectorADClient(ctx)

	var state resourceConnectorData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &pcaconnectorad.DeleteConnectorInput{
		ConnectorArn: aws.String(state.ID.ValueString()),
	}

	_, err := conn.DeleteConnector(ctx, in)

	if err != nil {
		var nfe *awstypes.ResourceNotFoundException
		if errors.As(err, &nfe) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionDeleting, ResNameConnector, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	deleteTimeout := r.DeleteTimeout(ctx, state.Timeouts)
	_, err = waitConnectorDeleted(ctx, conn, state.ID.ValueString(), deleteTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.PCAConnectorAD, create.ErrActionWaitingForDeletion, ResNameConnector, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceConnector) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
func (r *resourceConnector) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	r.SetTagsAll(ctx, request, response)
}

func waitConnectorCreated(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*pcaconnectorad.GetConnectorOutput, error) {
	stateConf := &retry.StateChangeConf{
		Pending:                   []string{string(awstypes.ConnectorStatusCreating)},
		Target:                    []string{string(awstypes.ConnectorStatusActive)},
		Refresh:                   statusConnector(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*pcaconnectorad.GetConnectorOutput); ok {
		return out, err
	}

	return nil, err
}

func waitConnectorDeleted(ctx context.Context, conn *pcaconnectorad.Client, id string, timeout time.Duration) (*pcaconnectorad.GetConnectorOutput, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{string(awstypes.ConnectorStatusDeleting), string(awstypes.ConnectorStatusActive)},
		Target:  []string{},
		Refresh: statusConnector(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*pcaconnectorad.GetConnectorOutput); ok {
		return out, err
	}

	return nil, err
}

func statusConnector(ctx context.Context, conn *pcaconnectorad.Client, id string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		out, err := findConnectorByID(ctx, conn, id)
		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return out, aws.ToString((*string)(&out.Status)), nil
	}
}

func findConnectorByID(ctx context.Context, conn *pcaconnectorad.Client, id string) (*awstypes.Connector, error) {
	in := &pcaconnectorad.GetConnectorInput{
		ConnectorArn: aws.String(id),
	}

	out, err := conn.GetConnector(ctx, in)
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

	if out == nil || out.Connector == nil {
		return nil, tfresource.NewEmptyResultError(in)
	}

	return out.Connector, nil
}

type resourceConnectorData struct {
	ARN                                       types.String   `tfsdk:"arn"`
	CertificateAuthorityARN                   types.String   `tfsdk:"certificate_authority_arn"`
	CertificateEnrollmentPolicyServerEndpoint types.String   `tfsdk:"certificate_enrollment_policy_server_endpoint"`
	DirectoryID                               types.String   `tfsdk:"directory_id"`
	ID                                        types.String   `tfsdk:"id"`
	SecurityGroupIDs                          types.Set      `tfsdk:"security_group_ids"`
	Tags                                      types.Map      `tfsdk:"tags"`
	TagsAll                                   types.Map      `tfsdk:"tags_all"`
	Timeouts                                  timeouts.Value `tfsdk:"timeouts"`
}
