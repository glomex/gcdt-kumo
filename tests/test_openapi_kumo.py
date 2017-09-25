# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

from gcdt.gcdt_openapi import get_openapi_defaults, get_openapi_scaffold_min, \
    get_openapi_scaffold_max, validate_tool_config

from gcdt_kumo import read_openapi


def test_scaffolding_default():
    spec = read_openapi()
    expected_defaults = {
        'defaults': {'non_config_commands': ['list'], 'validate': True}
    }

    kumo_defaults = get_openapi_defaults(spec, 'kumo')
    assert kumo_defaults == expected_defaults
    validate_tool_config(spec, {'kumo': kumo_defaults})


def test_scaffolding_sample_min():
    spec = read_openapi()
    expected_sample = {
        'stack': {'StackName': 'team-dev-my-application-stack'}
    }

    kumo_sample = get_openapi_scaffold_min(spec, 'kumo')
    assert kumo_sample == expected_sample
    validate_tool_config(spec, {'kumo': kumo_sample})


def test_scaffolding_sample_max():
    spec = read_openapi()
    expected_sample = {
        'stack': {
            'NotificationARNs': {
                'NotificationARNs': ['arn:aws:sns:eu-west-1:123456789012:mytopic1']},
            'RoleARN': 'arn:aws:iam::<AccountID>:role/<CloudFormationRoleName>',
            'StackName': 'team-dev-my-application-stack',
            'TemplateBody': 'value3',
            'artifactBucket': 'string'
        },
        'parameters': {'any_prop2': 42, u'any_prop1': u'string'},
        'defaults': {'validate': True, 'non_config_commands': ['list']},
        'deployment': {'DisableStop': True}
    }

    kumo_sample = get_openapi_scaffold_max(spec, 'kumo')
    print(kumo_sample)
    assert kumo_sample == expected_sample
    validate_tool_config(spec, {'kumo': kumo_sample})
