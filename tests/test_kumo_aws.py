# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import os

from pyhocon import ConfigFactory
from pyhocon.config_tree import ConfigTree
from nose.tools import assert_equal, assert_false, assert_is_not, \
    assert_regexp_matches, assert_is_not_none, assert_true
import pytest

from gcdt.kumo_core import load_cloudformation_template, list_stacks, \
    print_parameter_diff, are_credentials_still_valid, deploy_stack, \
    delete_stack, create_change_set, _get_stack_name, describe_change_set, \
    _get_artifact_bucket, _s3_upload, _get_stack_state
from gcdt.kumo_util import ensure_ebs_volume_tags_ec2_instance, \
    ensure_ebs_volume_tags_autoscaling_group
from gcdt.servicediscovery import get_outputs_for_stack
from gcdt.s3 import prepare_artifacts_bucket

from .helpers_aws import check_preconditions
from .helpers_aws import cleanup_buckets, awsclient  # fixtures!
from . import here


# read template and config
config_simple_stack = ConfigFactory.parse_file(
    here('resources/simple_cloudformation_stack/settings_dev.conf')
)

config_ec2 = ConfigFactory.parse_file(
    here('resources/sample_ec2_cloudformation_stack/settings_dev.conf')
)

config_autoscaling = ConfigFactory.parse_file(
    here('resources/sample_autoscaling_cloudformation_stack/settings_dev.conf')
)


@pytest.fixture(scope='function')  # 'function' or 'module'
def simple_cloudformation_stack(awsclient):
    # create a stack we use for the test lifecycle
    #print_parameter_diff(awsclient, config_simple_stack)
    are_credentials_still_valid(awsclient)
    cloudformation_simple_stack, _ = load_cloudformation_template(
        here('resources/simple_cloudformation_stack/cloudformation.py')
    )
    exit_code = deploy_stack(awsclient, config_simple_stack,
                             cloudformation_simple_stack,
                             override_stack_policy=False)
    assert not exit_code

    yield 'infra-dev-kumo-sample-stack'
    # cleanup
    exit_code = delete_stack(awsclient, config_simple_stack)
    # check whether delete was completed!
    assert not exit_code, 'delete_stack was not completed please make sure to clean up the stack manually'


@pytest.fixture(scope='function')  # 'function' or 'module'
def simple_cloudformation_stack_folder():
    # helper to get into the sample folder so kumo can find cloudformation.py
    cwd = (os.getcwd())
    os.chdir(here('./resources/simple_cloudformation_stack/'))
    yield
    # cleanup
    os.chdir(cwd)  # cd back to original folder


@pytest.fixture(scope='function')  # 'function' or 'module'
def sample_ec2_cloudformation_stack_folder():
    # helper to get into the sample folder so kumo can find cloudformation.py
    cwd = (os.getcwd())
    os.chdir(here('./resources/sample_ec2_cloudformation_stack/'))
    yield
    # cleanup
    os.chdir(cwd)  # cd back to original folder


@pytest.fixture(scope='function')  # 'function' or 'module'
def sample_cloudformation_stack_with_hooks(awsclient):
    # create a stack we use for the test lifecycle
    are_credentials_still_valid(awsclient)
    cloudformation_stack, _ = load_cloudformation_template(
        here('resources/sample_cloudformation_stack_with_hooks/cloudformation.py')
    )
    config_stack = ConfigFactory.parse_file(
        here('resources/sample_cloudformation_stack_with_hooks/settings_dev.conf')
    )
    exit_code = deploy_stack(awsclient, config_stack,
                             cloudformation_stack,
                             override_stack_policy=False)
    assert not exit_code

    yield 'infra-dev-kumo-sample-stack-with-hooks'
    # cleanup
    exit_code = delete_stack(awsclient, config_stack)
    # check whether delete was completed!
    assert not exit_code, 'delete_stack was not completed please make sure to clean up the stack manually'


@pytest.mark.aws
@check_preconditions
def test_s3_upload(cleanup_buckets, awsclient):
    upload_conf = ConfigFactory.parse_file(
        here('resources/simple_cloudformation_stack/settings_upload_dev.conf')
    )

    region = awsclient.get_client('s3').meta.region_name
    account = os.getenv('ACCOUNT', None)
    # add account prefix to artifact bucket config
    if account:
        upload_conf['cloudformation']['artifactBucket'] = \
            '%s-unittest-kumo-artifact-bucket' % account

    artifact_bucket = _get_artifact_bucket(upload_conf)
    prepare_artifacts_bucket(awsclient, artifact_bucket)
    cleanup_buckets.append(artifact_bucket)
    dest_key = 'kumo/%s/%s-cloudformation.json' % (region,
                                                   _get_stack_name(upload_conf))
    expected_s3url = 'https://s3-%s.amazonaws.com/%s/%s' % (region,
                                                            artifact_bucket,
                                                            dest_key)
    cloudformation_simple_stack, _ = load_cloudformation_template(
        here('resources/simple_cloudformation_stack/cloudformation.py')
    )
    actual_s3url = _s3_upload(awsclient, upload_conf,
                              cloudformation_simple_stack)
    assert expected_s3url == actual_s3url


# most kumo-operations which rely on a stack on AWS can not be tested in isolation
# since the stack creation for a simple stack takes some time we decided
# to test the stack related operations together

#@pytest.fixture(scope='function')  # 'function' or 'module'
#def cleanup_stack(awsclient):
#    """Remove the stack to cleanup after test run.#
#
#    This is intended to be called during test teardown"""
#    yield
#    # cleanup
#    exit_code = delete_stack(awsclient, config_simple_stack)
#    # check whether delete was completed!
#    assert_false(exit_code, 'delete_stack was not completed\n' +
#                 'please make sure to clean up the stack manually')


@pytest.fixture(scope='function')  # 'function' or 'module'
def cleanup_stack_autoscaling(awsclient):
    """Remove the autoscaling stack to cleanup after test run.

    This is intended to be called during test teardown"""
    yield
    # cleanup
    exit_code = delete_stack(awsclient, config_autoscaling)
    # check whether delete was completed!
    assert_false(exit_code, 'delete_stack was not completed\n' +
                 'please make sure to clean up the stack manually')


@pytest.fixture(scope='function')  # 'function' or 'module'
def cleanup_stack_ec2(awsclient):
    """Remove the ec2 stack to cleanup after test run.

    This is intended to be called during test teardown"""
    yield
    # cleanup
    exit_code = delete_stack(awsclient, config_ec2)
    # check whether delete was completed!
    assert_false(exit_code, 'delete_stack was not completed\n' +
                 'please make sure to clean up the stack manually')


@pytest.mark.aws
@check_preconditions
def test_kumo_stack_lifecycle(awsclient, simple_cloudformation_stack):
    # create a stack we use for the test lifecycle
    #print_parameter_diff(awsclient, config_simple_stack)
    #are_credentials_still_valid(awsclient)
    cloudformation_simple_stack, _ = load_cloudformation_template(
        here('resources/simple_cloudformation_stack/cloudformation.py')
    )
    #exit_code = deploy_stack(awsclient, config_simple_stack,
    #                         cloudformation_simple_stack,
    #                         override_stack_policy=False)
    #assert_equal(exit_code, 0)

    # preview (with identical stack)
    # TODO: add more asserts!
    change_set_name, stackname = \
        create_change_set(awsclient, config_simple_stack,
                          cloudformation_simple_stack)
    assert_equal(stackname, _get_stack_name(config_simple_stack))
    assert_is_not(change_set_name, '')
    describe_change_set(awsclient, change_set_name, stackname)

    # update the stack
    print_parameter_diff(awsclient, config_simple_stack)
    exit_code = deploy_stack(awsclient, config_simple_stack,
                             cloudformation_simple_stack,
                             override_stack_policy=False)
    assert_equal(exit_code, 0)


@pytest.mark.aws
@check_preconditions
def test_kumo_utils_ensure_autoscaling_ebs_tags(cleanup_stack_autoscaling,
                                                awsclient):
    are_credentials_still_valid(awsclient)
    cloudformation_autoscaling, _ = load_cloudformation_template(
        here('resources/sample_autoscaling_cloudformation_stack/cloudformation.py')
    )

    exit_code = deploy_stack(awsclient, config_autoscaling,
                             cloudformation_autoscaling,
                             override_stack_policy=False)
    assert_equal(exit_code, 0)
    stack_name = _get_stack_name(config_autoscaling)
    stack_output = get_outputs_for_stack(awsclient, stack_name)
    as_group_name = stack_output.get('AutoScalingGroupName', None)
    assert_is_not_none(as_group_name)
    tags_v1 = [{'Key': 'kumo-test', 'Value': 'version1'}]
    ensure_ebs_volume_tags_autoscaling_group(awsclient, as_group_name,
                                             tags_v1)

    autoscale_filter = {
        'Name': 'tag:aws:autoscaling:groupName',
        'Values': [as_group_name]
    }
    client_ec2 = awsclient.get_client('ec2')
    response = client_ec2.describe_instances(Filters=[autoscale_filter])
    for r in response['Reservations']:
        for i in r['Instances']:
            volumes = client_ec2.describe_volumes(Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [i['InstanceId']]
                }
            ])
            for vol in volumes['Volumes']:
                for tag in tags_v1:
                    assert check_volume_tagged(vol, tag)
    tags_v2 = [{'Key': 'kumo-test', 'Value': 'version2'}]
    ensure_ebs_volume_tags_autoscaling_group(awsclient, as_group_name, tags_v2)
    for r in response['Reservations']:
        for i in r['Instances']:
            volumes = client_ec2.describe_volumes(Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [i['InstanceId']]
                }
            ])
            for vol in volumes['Volumes']:
                for tag in tags_v2:
                    assert_true(check_volume_tagged(vol, tag))
                for tag in tags_v1:
                    assert_false(check_volume_tagged(vol, tag))


@pytest.mark.aws
@check_preconditions
def test_kumo_utils_ensure_ebs_tags(cleanup_stack_ec2, awsclient):
    are_credentials_still_valid(awsclient)
    cloudformation_ec2, _ = load_cloudformation_template(
        here('resources/sample_ec2_cloudformation_stack/cloudformation.py')
    )
    exit_code = deploy_stack(awsclient, config_ec2, cloudformation_ec2,
                             override_stack_policy=False)
    assert_equal(exit_code, 0)

    stack_name = _get_stack_name(config_ec2)
    stack_output = get_outputs_for_stack(awsclient, stack_name)
    instance_id = stack_output.get('InstanceId', None)
    assert_is_not_none(instance_id)
    tags = [{'Key': 'kumo-test', 'Value': 'Success'}]
    ensure_ebs_volume_tags_ec2_instance(awsclient, instance_id, tags)
    client_ec2 = awsclient.get_client('ec2')
    volumes = client_ec2.describe_volumes(Filters=[
        {
            'Name': 'attachment.instance-id',
            'Values': [instance_id]
        }
    ])
    for vol in volumes['Volumes']:
        for tag in tags:
            assert_true(check_volume_tagged(vol, tag))


def check_volume_tagged(vol, tag):
    if 'Tags' in vol:
        if tag in vol['Tags']:
            return True
        else:
            return False
    else:
        return False


@pytest.mark.aws
@check_preconditions
def test_get_stack_state(awsclient, simple_cloudformation_stack):
    state = _get_stack_state(awsclient.get_client('cloudformation'),
                             simple_cloudformation_stack)
    assert state in ['CREATE_IN_PROGRESS', 'CREATE_COMPLETE']


@pytest.mark.aws
@check_preconditions
def test_call_hook(awsclient, sample_cloudformation_stack_with_hooks):
    # note: asserts for parameters are located in the hook
    state = _get_stack_state(awsclient.get_client('cloudformation'),
                             sample_cloudformation_stack_with_hooks)
    assert state in ['CREATE_IN_PROGRESS', 'CREATE_COMPLETE']


# TODO
'''
are_credentials_still_valid
'''