from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from aws_cdk import (
    aws_config as config
)
from .errors import RdkParametersInvalidError
import json

@dataclass
class ManagedRule:
    """
    Defines Managed Rule.

    Parameters:

    * **`identifier`** (_str_): The policy definition containing the logic for your AWS Config Custom Policy rule.
    * **`config_rule_name`** (_str_): Optional - A name for the AWS Config rule. Default: - CloudFormation generated name
    * **`description`** (_str_): Optional - A description about this AWS Config rule. Default: - No description
    * **`input_parameters`** (_Dict[str, Any]_): Optional - Input parameter values that are passed to the AWS Config rule. Default: - No input parameters
    * **`maximum_execution_frequency`** (_MaximumExecutionFrequency_): Optional - The maximum frequency at which the AWS Config rule runs evaluations. Default: MaximumExecutionFrequency.TWENTY_FOUR_HOURS
    * **`rule_scope`** (_RuleScope_): Optional - Defines which resources trigger an evaluation for an AWS Config rule. Default: - evaluations for the rule are triggered when any resource in the recording group changes.

    """

    identifier: config.ManagedRuleIdentifiers = field(init=False)
    config_rule_name: Optional[str] = None
    description: Optional[str] = None
    input_parameters: Optional[Dict[str, Any]] = None
    maximum_execution_frequency: Optional[config.MaximumExecutionFrequency] = config.MaximumExecutionFrequency.TWENTY_FOUR_HOURS
    rule_scope: Optional[config.RuleScope] = None

    def __init__(self, rule_parameters: dict):
        param = rule_parameters["Parameters"]
        if param["SourceIdentifier"]:
            try:
                self.identifier = getattr(config.ManagedRuleIdentifiers, param["SourceIdentifier"].upper().replace("-", "_"))
            except:
                raise RdkParametersInvalidError("Invalid parameters found in Parameters.SourceIdentifier. Please review https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html")
        if "Description" in param:
            self.description = param["Description"]
        if "InputParameters" in param:
            self.input_parameters = json.loads(param["InputParameters"])
        if "MaximumExecutionFrequency" in param:
            try:
                maximum_execution_frequency = getattr(config.MaximumExecutionFrequency, param["SourcePeriodic"].upper())
            except:
                raise RdkParametersInvalidError("Invalid parameters found in Parameters.MaximumExecutionFrequency. Please review https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configrule.html#cfn-config-configrule-maximumexecutionfrequency")                
            self.maximum_execution_frequency = maximum_execution_frequency
        if "SourceEvents" in param:
            try:
                source_events = getattr(config.ResourceType, param["SourceEvents"].upper().replace("AWS::", "").replace("::", "_"))
            except:
                raise RdkParametersInvalidError("Invalid parameters found in Parameters.SourceEvents. Please review https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html")                
            self.rule_scope = config.RuleScope.from_resources([source_events])