terraform {
  required_version = "~> 1"
  required_providers {
    aws = {
      source  = "registry.terraform.io/hashicorp/aws"
      version = "~> 5"
    }
  }
}

provider "aws" {
  default_tags {
    tags = {
      Purpose = "SfnEKSCall"
    }
  }
}

locals {
  name = "get-deployments"
}

resource "aws_iam_role" "this" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.allow_assume_by_sfn.json
}
data "aws_iam_policy_document" "allow_assume_by_sfn" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "states.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "eks_access" {
  name   = "eks-access"
  role   = aws_iam_role.this.name
  policy = data.aws_iam_policy_document.allow_eks_access.json
}
data "aws_iam_policy_document" "allow_eks_access" {
  statement {
    actions = [
      "eks:DescribeCluster",
    ]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy" "xray_access" {
  name   = "xray-access"
  role   = aws_iam_role.this.name
  policy = data.aws_iam_policy_document.allow_xray_access.json
}
data "aws_iam_policy_document" "allow_xray_access" {
  statement {
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy" "logs_access" {
  name   = "logs-access"
  role   = aws_iam_role.this.name
  policy = data.aws_iam_policy_document.allow_logs_access.json
}
data "aws_iam_policy_document" "allow_logs_access" {
  statement {
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_sfn_state_machine" "this" {
  name     = local.name
  role_arn = aws_iam_role.this.arn

  definition = <<-EOT
  {
    "Comment": "call 'kubectl get deployments -A'",
    "StartAt": "GetClusterInfo",
    "States": {
      "GetClusterInfo": {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:eks:describeCluster",
        "Parameters": {
          "Name.$": "$.clusterName"
        },
        "ResultPath": "$.clusterInfo",
        "Next": "CallGetDeployments"
      },
      "CallGetDeployments": {
        "Type": "Task",
        "Resource": "arn:aws:states:::eks:call",
        "Parameters": {
          "ClusterName.$": "$.clusterName",
          "CertificateAuthority.$": "$.clusterInfo.Cluster.CertificateAuthority.Data",
          "Endpoint.$": "$.clusterInfo.Cluster.Endpoint",
          "Method": "GET",
          "Path": "/apis/apps/v1/deployments"
        },
        "End": true
      }
    }
  }
  EOT
  logging_configuration {
    include_execution_data = true
    level                  = "ERROR"
    log_destination        = "${aws_cloudwatch_log_group.this.arn}:*"
  }
  tracing_configuration {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/vendedlogs/states/${local.name}"
  retention_in_days = 7
}
