# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import troposphere
from gcdt_kumo.kumo_util import StackLookup, fix_deprecated_kumo_config


def test_StackLookup():
    # used in cloudformation!
    # Create EC2 Cloudformation template with troposphere
    t = troposphere.Template()
    t.add_version('2010-09-09')
    t.add_description('gcdt unit-tests')

    lambda_lookup_arn = 'lookup:stack:%s:EC2BasicsLambdaArn' % 'dp-dev'
    stack_lookup = StackLookup(t, lambda_lookup_arn)
    # as_reference: Is the parameter a reference (Default) or a string
    vpcid = stack_lookup.get_att('vpcid', as_reference=False)
    assert vpcid.data == {'Fn::GetAtt': ['StackOutput', 'vpcid']}


def test_fix_deprecated_kumo_config():
    config = {
        'kumo': {
            'cloudformation': {
                'StackName': 'my_stack_name',
                'InstanceType': 't2.micro'
            }
        }
    }
    exp_config = {
        'kumo': {
            'stack': {
                'StackName': 'my_stack_name'
            },
            'parameters': {
                'InstanceType': 't2.micro'
            }
        }
    }

    fix_deprecated_kumo_config(config)
    assert config == exp_config


def test_fix_deprecated_kumo_config_no_change():
    config = {
        'kumo': {
            'stack': {
                'StackName': 'my_stack_name'
            },
            'parameters': {
                'InstanceType': 't2.micro'
            }
        }
    }
    exp_config = {
        'kumo': {
            'stack': {
                'StackName': 'my_stack_name'
            },
            'parameters': {
                'InstanceType': 't2.micro'
            }
        }
    }

    fix_deprecated_kumo_config(config)
    assert config == exp_config


def test_fix_deprecated_kumo_config_no_parameters():
    config = {
        'kumo': {
            'cloudformation': {
                'StackName': 'my_stack_name',
            }
        }
    }
    exp_config = {
        'kumo': {
            'stack': {
                'StackName': 'my_stack_name'
            }
        }
    }

    fix_deprecated_kumo_config(config)
    assert config == exp_config
