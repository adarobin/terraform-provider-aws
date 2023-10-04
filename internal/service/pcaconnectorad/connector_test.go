// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pcaconnectorad_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pcaconnectorad"
	"github.com/aws/aws-sdk-go-v2/service/pcaconnectorad/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/names"

	tfpcaconnectorad "github.com/hashicorp/terraform-provider-aws/internal/service/pcaconnectorad"
)

// TIP: File Structure. The basic outline for all test files should be as
// follows. Improve this resource's maintainability by following this
// outline.
//
// 1. Package declaration (add "_test" since this is a test file)
// 2. Imports
// 3. Unit tests
// 4. Basic test
// 5. Disappears test
// 6. All the other tests
// 7. Helper functions (exists, destroy, check, etc.)
// 8. Functions that return Terraform configurations

// TIP: ==== UNIT TESTS ====
// This is an example of a unit test. Its name is not prefixed with
// "TestAcc" like an acceptance test.
//
// Unlike acceptance tests, unit tests do not access AWS and are focused on a
// function (or method). Because of this, they are quick and cheap to run.
//
// In designing a resource's implementation, isolate complex bits from AWS bits
// so that they can be tested through a unit test. We encourage more unit tests
// in the provider.
//
// Cut and dry functions using well-used patterns, like typical flatteners and
// expanders, don't need unit testing. However, if they are complex or
// intricate, they should be unit tested.
func TestConnectorExampleUnitTest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		TestName string
		Input    string
		Expected string
		Error    bool
	}{
		{
			TestName: "empty",
			Input:    "",
			Expected: "",
			Error:    true,
		},
		{
			TestName: "descriptive name",
			Input:    "some input",
			Expected: "some output",
			Error:    false,
		},
		{
			TestName: "another descriptive name",
			Input:    "more input",
			Expected: "more output",
			Error:    false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()
			got, err := tfpcaconnectorad.FunctionFromResource(testCase.Input)

			if err != nil && !testCase.Error {
				t.Errorf("got error (%s), expected no error", err)
			}

			if err == nil && testCase.Error {
				t.Errorf("got (%s) and no error, expected error", got)
			}

			if got != testCase.Expected {
				t.Errorf("got %s, expected %s", got, testCase.Expected)
			}
		})
	}
}

// TIP: ==== ACCEPTANCE TESTS ====
// This is an example of a basic acceptance test. This should test as much of
// standard functionality of the resource as possible, and test importing, if
// applicable. We prefix its name with "TestAcc", the service, and the
// resource name.
//
// Acceptance test access AWS and cost money to run.
func TestAccPCAConnectorADConnector_basic(t *testing.T) {
	ctx := acctest.Context(t)
	// TIP: This is a long-running test guard for tests that run longer than
	// 300s (5 min) generally.
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var connector pcaconnectorad.DescribeConnectorResponse
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_pcaconnectorad_connector.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.PCAConnectorADEndpointID)
			testAccPreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.PCAConnectorADEndpointID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckConnectorDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccConnectorConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckConnectorExists(ctx, resourceName, &connector),
					resource.TestCheckResourceAttr(resourceName, "auto_minor_version_upgrade", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "maintenance_window_start_time.0.day_of_week"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "user.*", map[string]string{
						"console_access": "false",
						"groups.#":       "0",
						"username":       "Test",
						"password":       "TestTest1234",
					}),
					acctest.MatchResourceAttrRegionalARN(resourceName, "arn", "pcaconnectorad", regexache.MustCompile(`connector:+.`)),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"apply_immediately", "user"},
			},
		},
	})
}

func TestAccPCAConnectorADConnector_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var connector pcaconnectorad.DescribeConnectorResponse
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_pcaconnectorad_connector.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.PCAConnectorADEndpointID)
			testAccPreCheck(t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.PCAConnectorADEndpointID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckConnectorDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccConnectorConfig_basic(rName, testAccConnectorVersionNewer),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckConnectorExists(ctx, resourceName, &connector),
					// TIP: The Plugin-Framework disappears helper is similar to the Plugin-SDK version,
					// but expects a new resource factory function as the third argument. To expose this
					// private function to the testing package, you may need to add a line like the following
					// to exports_test.go:
					//
					//   var ResourceConnector = newResourceConnector
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfpcaconnectorad.ResourceConnector, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckConnectorDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).PCAConnectorADClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_pcaconnectorad_connector" {
				continue
			}

			input := &pcaconnectorad.DescribeConnectorInput{
				ConnectorId: aws.String(rs.Primary.ID),
			}
			_, err := conn.DescribeConnector(ctx, &pcaconnectorad.DescribeConnectorInput{
				ConnectorId: aws.String(rs.Primary.ID),
			})
			if errs.IsA[*types.ResourceNotFoundException](err) {
				return nil
			}
			if err != nil {
				return create.Error(names.PCAConnectorAD, create.ErrActionCheckingDestroyed, tfpcaconnectorad.ResNameConnector, rs.Primary.ID, err)
			}

			return create.Error(names.PCAConnectorAD, create.ErrActionCheckingDestroyed, tfpcaconnectorad.ResNameConnector, rs.Primary.ID, errors.New("not destroyed"))
		}

		return nil
	}
}

func testAccCheckConnectorExists(ctx context.Context, name string, connector *pcaconnectorad.DescribeConnectorResponse) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.PCAConnectorAD, create.ErrActionCheckingExistence, tfpcaconnectorad.ResNameConnector, name, errors.New("not found"))
		}

		if rs.Primary.ID == "" {
			return create.Error(names.PCAConnectorAD, create.ErrActionCheckingExistence, tfpcaconnectorad.ResNameConnector, name, errors.New("not set"))
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).PCAConnectorADClient(ctx)
		resp, err := conn.DescribeConnector(ctx, &pcaconnectorad.DescribeConnectorInput{
			ConnectorId: aws.String(rs.Primary.ID),
		})

		if err != nil {
			return create.Error(names.PCAConnectorAD, create.ErrActionCheckingExistence, tfpcaconnectorad.ResNameConnector, rs.Primary.ID, err)
		}

		*connector = *resp

		return nil
	}
}

func testAccPreCheck(ctx context.Context, t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).PCAConnectorADClient(ctx)

	input := &pcaconnectorad.ListConnectorsInput{}
	_, err := conn.ListConnectors(ctx, input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}
	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccCheckConnectorNotRecreated(before, after *pcaconnectorad.DescribeConnectorResponse) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if before, after := aws.ToString(before.ConnectorId), aws.ToString(after.ConnectorId); before != after {
			return create.Error(names.PCAConnectorAD, create.ErrActionCheckingNotRecreated, tfpcaconnectorad.ResNameConnector, aws.ToString(before.ConnectorId), errors.New("recreated"))
		}

		return nil
	}
}

func testAccConnectorConfig_basic(rName, version string) string {
	return fmt.Sprintf(`
resource "aws_security_group" "test" {
  name = %[1]q
}

resource "aws_pcaconnectorad_connector" "test" {
  connector_name             = %[1]q
  engine_type             = "ActivePCAConnectorAD"
  engine_version          = %[2]q
  host_instance_type      = "pcaconnectorad.t2.micro"
  security_groups         = [aws_security_group.test.id]
  authentication_strategy = "simple"
  storage_type            = "efs"

  logs {
    general = true
  }

  user {
    username = "Test"
    password = "TestTest1234"
  }
}
`, rName, version)
}
