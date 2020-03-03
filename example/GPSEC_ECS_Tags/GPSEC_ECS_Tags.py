# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import os
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType
from rdklib.util.evaluations import clean_up_old_evaluations

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = True

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900

#############
# Main Code #
#############

################################
# Supporting Functions for ECS #
################################

# import regex module for tag_regex_filtering
import re

# Regex for getting name of taskDefinition and Cluster
nameregex = '\/(.*)'

# Compliance result strings
non_compliant_str = 'One or More Tags are NON_COMPLIANT on ECS Resource ({}). Results: ({})'
compliant_str = 'Tags are COMPLIANT on ECS Resource ({})'
no_tags_str = "NO Tags at all on ECS Resource ({})"
old_arn_str = "({}) uses old ARN and does not support TAGS"

# Fetch all items in a given boto3 query, in the case of a truncated response with a NextToken
def fetch_all_items(client, method, response_key, **kwargs):
    """
    client: The boto3 client
    method: The boto3 method to be fetched (e.g. ecs_client.list_clusters)
    kwargs: The parameter name and value for a given boto3 method (e.g. ecs_client.list_services(cluster=clusterArn))
    """
    if kwargs:
        response = method(**kwargs)
    else:
        response = method()

    items = response[response_key]
    next_token = response.get('NextToken')
    while next_token:
        response = client.method(NextToken=next_token)
        items = items + response[response_key]
        next_token = response.get('NextToken')

    return items

# Go through each tag individually
def tag_regex_filtering(tags):
    '''
    Applies regex filters to each tag to evaluate compliance
    Usage: Provide a list of tags and this function will iterate through the list and return a list of results
    '''
    # Empty list for results
    tags_checked = []

    # Regex Filters for UAI value tags
    uai_value_regex_filter = "(uai[\d]{7})"
    # Regex Filters for ENV value tags
    env_value_regex_filter = "(?:^)(prd|stg|qa|tst|dev|lab)(?:(?= )|$)"
    # Regex Filters for Name value tags
    name_value_regex_filter = "(\s)"

    for tag in tags:

        if "uai" in tag['key'].lower():
            if re.search(uai_value_regex_filter, tag['value']):
                tags_checked.append([tag['key'],"COMPLIANT"])
            else:
                tags_checked.append([tag['key'],"NON_COMPLIANT"])
        elif "env" in tag['key'].lower():
            if re.search(env_value_regex_filter, tag['value']):
                tags_checked.append([tag['key'],"COMPLIANT"])
            else:
                tags_checked.append([tag['key'],"NON_COMPLIANT"])
        elif "Name" in tag['key'] or "app" in tag['key'].lower():
            if re.search(name_value_regex_filter, tag['value']):
                ##If space found in value then NON_COMPLIANT
                tags_checked.append([tag['key'],"NON_COMPLIANT"])
            else:
                tags_checked.append([tag['key'],"COMPLIANT"])
        else:
            # If none of the tags are part of the compliant tags set then the service is marked as NON_COMPLIANT
            no_tags_result = 'NO_TAGS'
            tags_checked.append(no_tags_result)
    return tags_checked

def taskDefinition_eval(ecs_service, task_definition_arn, minimum_number_compliant, evaluations, event):
    '''
    Provide the client for connection, a taskDefinition along with the number of tags that must be compliant for the taskDefinition to be COMPLIANT
    evaluations and event are passed on by the evaluate_compliance function.
    Example: taskDefinition(ecs_service, 'arn:aws:ecs:us-east-1:533271940600:task-definition/users:1', 3, evaluations, event)

    Use the given task definition ARN to:
    1) retrieve the name of the taskDefinition
    2) Get all the tags in the given task_definition_arn
    3a) Get the length of tags in the specified task_definition_arn
    3b) Identify If the length of tags is zero, if so then this resource has no tags and therefore NON_COMPLIANT
    4a) Run regex to validate tags in given task_definition_arn
    4b) Check the results, if there's even one NON_COMPLIANT tag then the whole cluster is marked as NON_COMPLIANT
    '''
    resource_type = 'AWS::ECS::TaskDefinition'
    # 1) retrieve the name of the taskDefinition
    task_definition_name = re.findall(nameregex, task_definition_arn)[0]
    print("Processing Task Definition:", task_definition_name)

    # 2) Use the function previously defined to get all the tags in the current task definition
    # this varies by each task_definition_arn as it's retrieving the tags for each ARN
    tags_in_taskDefinition = fetch_all_items(ecs_service, ecs_service.list_tags_for_resource, 'tags', resourceArn=task_definition_arn)

    # 3a) Get the length of tags in the specified task_definition_arn
    length_tags_in_taskDefinition = len(tags_in_taskDefinition)

    # 3b) Identify If the length of tags is zero, if so then this resource has no tags and therefore NON_COMPLIANT
    if length_tags_in_taskDefinition == 0:
        annotation = no_tags_str.format(task_definition_name)[:255]
        evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=task_definition_arn,resourceType=resource_type,annotation=annotation))
    else:
        # 4a) Run regex to validate tags in given task_definition_arn
        tags_compliance = tag_regex_filtering(tags_in_taskDefinition)
        compliance_count = str(tags_compliance).count(" 'COMPLIANT']")
        # 4b) Check the results, if there's even one NON_COMPLIANT tag then the whole cluster is marked as NON_COMPLIANT
        if compliance_count == minimum_number_compliant:
            annotation = compliant_str.format(task_definition_name)[:255]
            evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=task_definition_arn,resourceType=resource_type,annotation=annotation))
        else:
            annotation = non_compliant_str.format(task_definition_name, str(tags_compliance))[:255]
            evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=task_definition_arn,resourceType=resource_type,annotation=annotation))


def service_eval(ecs_service, service_arn, minimum_number_compliant, service_name, evaluations, event):
    '''
    Provide the client for connection, a service_arn along with the number of tags that must be compliant for the service to be COMPLIANT
    service_name, evaluations and event are passed on by the evaluate_compliance function.

    Example: service_eval(ecs_service, 'arn:aws:ecs:us-east-1:533271940600:service/fargatecommandtest', 3, 'fargatecommandtest', evaluations, event)

    As of 9/9/2019 Tags are a new functionality for ECS,
    it's only supported for resources with the new ARN format which includes the Cluster in the name
    The following line checks the number of '/' to determine if the ARN is the old one or the new version that supports tags.
    Example of old ARN: arn:aws:ecs:us-east-1:123456789123:service/api
    Example of new ARN: arn:aws:ecs:us-east-1:123456789123:service/cluster_name/api

    This function will:
    1) Check the format of service_arn.
    2a) Check the length of tags for given service_arn
    2b) Sometimes there would be no tags on a resource, in this case the resource would be NON_COMPLIANT
    3a) Run tag_regex_filtering function to identify compliant/non-compliant tags
    3b) Count how many times the tags are compliant
    3c) If the number of compliant tags match the minimum_number_compliant then the service is compliant
    4) If the ARN of the service does not support tags then it's marked as NON_COMPLIANT
    '''
    resource_type = 'AWS::ECS::Service'
    # 1) Check the format of service_arn.
    # If the service_arn given uses the new naming convention then the tags feature is supported
    if sum(map(lambda x : 1 if '/' in x else 0, service_arn)) > 1:
        tags_in_service = fetch_all_items(ecs_service, ecs_service.list_tags_for_resource, 'tags', resourceArn=service_arn)
        # 2a) Check the length of tags for given service_arn
        len_tags_in_service = len(tags_in_service)
        print("Processing Service:", service_name)

        # 2b) Sometimes there would be no tags on a resource, in this case the resource would be NON_COMPLIANT
        if len_tags_in_service == 0:
            annotation = no_tags_str.format(service_name)[:255]
            evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=service_arn,resourceType=resource_type,annotation=annotation))
        else:
            # 3a) Run tag_regex_filtering function to identify compliant/non-compliant tags
            tags_compliance = tag_regex_filtering(tags_in_service)
            # 3b) Count how many times the tags are compliant
            compliance_count = str(tags_compliance).count(" 'COMPLIANT']")
            # 3c) If the number of compliant tags match the minimum_number_compliant then the service is compliant
            if compliance_count == minimum_number_compliant:
                annotation = compliant_str.format(service_name)[:255]
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=service_arn,resourceType=resource_type,annotation=annotation))
            else:
                annotation = non_compliant_str.format(service_name, str(tags_compliance))[:255]
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=service_arn,resourceType=resource_type,annotation=annotation))
    # 4) If the ARN of the service does not support tags then it's marked as COMPLIANT
    else:
        annotation = old_arn_str.format(service_name)[:255]
        evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,resourceId=service_arn,resourceType=resource_type,annotation=annotation))

def cluster_eval(ecs_service, cluster, minimum_number_compliant, clustername, evaluations, event):
    '''
    Provide a cluster ARN along with the number of tags that must be compliant for the cluster to be COMPLIANT
    evaluations and event are passed on by the evaluate_compliance function.

    Example: service_eval(ecs_service, 'arn:aws:ecs:us-east-1:533271940600:cluster/FargateCluster1', 3, 'FargateCluster1', evaluations, event)

    This function will:
    1) Check tags in cluster, if no tags then resource is NON_COMPLIANT
    2) Run tag_regex_filtering function to identify compliant/non-compliant tags
    3a) Count how many times the tags are compliant
    3b) If the number of compliant tags match the minimum_number_compliant then the service is compliant
    3c) If the minimum_number_compliant does not match the results then the resource is marked as NON_COMPLIANT
    '''
    resource_type = 'AWS::ECS::Cluster'
    tags_in_cluster = fetch_all_items(ecs_service, ecs_service.list_tags_for_resource, 'tags', resourceArn=cluster)

    # Sometimes there would be no tags on a resource, in this case the resource would be NON_COMPLIANT
    # 1) Check tags in cluster, if no tags then resource is NON_COMPLIANT
    if len(tags_in_cluster) == 0:
        annotation = no_tags_str.format(clustername)[:255]
        evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,cluster,resourceType=resource_type,annotation=annotation))
    else:
        # 2) Run tag_regex_filtering function to identify compliant/non-compliant tags
        tags_compliance = tag_regex_filtering(tags_in_cluster)
        # 3a) Count how many times the tags are compliant
        compliance_count = str(tags_compliance).count(" 'COMPLIANT']")

        # 3b) If the number of compliant tags match the minimum_number_compliant then the service is compliant
        if compliance_count == minimum_number_compliant:
            annotation = compliant_str.format(clustername)[:255]
            evaluations.append(Evaluation(ComplianceType.COMPLIANT,cluster,resourceType=resource_type,annotation=annotation))
        # 3c) If the minimum_number_compliant does not match the results then the resource is marked as NON_COMPLIANT
        else:
            annotation = non_compliant_str.format(clustername, str(tags_compliance))[:255]
            evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,cluster,resourceType=resource_type,annotation=annotation))

class GPSEC_ECS_Tags(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        """Form the evaluation(s) to be return to Config Rules

        Return either:
        None -- when no result needs to be displayed
        a list of Evaluation -- a list of evaluation object , built by Evaluation()

        Keyword arguments:
        event -- the event variable given in the lambda handler
        client_factory -- ClientFactory object to be used in this rule. It is defined in RDKLib.
        valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

        Advanced Notes:
        1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
        2 -- if a None or a list of Evaluation is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
        3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
        """

        # Define the ECS boto3 connection
        ecs_service = client_factory.build_client('ecs')

        # Create a list of all the clusters using the previously defined function
        list_clusters = fetch_all_items(ecs_service, ecs_service.list_clusters, 'clusterArns', maxResults=100)

        # Create a list of all the task_definitions using the previously defined function
        task_definition_arns = fetch_all_items(ecs_service, ecs_service.list_task_definitions, 'taskDefinitionArns', maxResults=100)


        # Create an empty list where the AWS Config Results will be stored.
        evaluations = []

        # Minimum number of tags that need to be compliant in order to mark resource as COMPLIANT in evaluations
        # This number should match the number of tags defined in the tag_regex_filtering function
        minimum_number_compliant = 3

        # This block of code checks tags in TaskDefinitions#####
        for task_definition_arn in task_definition_arns:
            taskDefinition_eval(ecs_service, task_definition_arn, minimum_number_compliant, evaluations, event)

        # Go through each cluster
        for cluster in list_clusters:

            clustername = re.findall(nameregex, cluster)[0]

            print("Processing Cluster:", clustername)
            # This block of code checks tags in Clusters############
            cluster_eval(ecs_service, cluster, minimum_number_compliant, clustername, evaluations, event)

            # This block of code checks tags in services############
            all_services_in_cluster = fetch_all_items(ecs_service, ecs_service.list_services, 'serviceArns', cluster=cluster,maxResults=100)
            if len(all_services_in_cluster) > 0:
                list_describe_services = ecs_service.describe_services(cluster=cluster, services=all_services_in_cluster)
                for service in list_describe_services['services']:
                    # Set the service ARN as a variable
                    service_arn = service['serviceArn']
                    service_name = service['serviceName']
                    service_eval(ecs_service, service_arn, minimum_number_compliant, service_name, evaluations, event)

        # If there are results return the evaluations
        if evaluations:
            # print(evaluations)
            latest_eval = [i.get_json() for i in evaluations]
            clean_up_old_evaluations(event, client_factory, latest_eval)
            return evaluations
        # if there are no results, return "NOT_APPLICABLE"
        else:
            return []

################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = GPSEC_ECS_Tags()
    evaluator = Evaluator(my_rule, os.environ.get('AWS_REGION'))
    print(event)
    return evaluator.handle(event, context)
