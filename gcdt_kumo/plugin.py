# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from copy import deepcopy

from gcdt.utils import dict_merge
from gcdt import gcdt_signals
from gcdt.gcdt_openapi import get_openapi_defaults, validate_tool_config

from .kumo_util import fix_deprecated_kumo_config
from . import read_openapi


# TODO: plugin functionality
# * scaffoling sample-min and sample-max


def incept_defaults(params):
    """incept defaults where needed (after config is read from file).
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    context, config = params
    # we need the defaults in all cases (especially if we do not have a config file)
    defaults = get_openapi_defaults(read_openapi(), 'kumo')
    if defaults:
        config_from_reader = deepcopy(config)
        if context['tool'] == 'kumo':
            dict_merge(config, {'kumo': defaults})
        else:
            # incept only 'defaults' section
            dict_merge(config, {'kumo': {'defaults': defaults['defaults']}})

        dict_merge(config, config_from_reader)


def fix_and_validate_config(params):
    """validate the config after lookups.
    :param params: context, config (context - the _awsclient, etc..
                   config - The stack details, etc..)
    """
    context, config = params
    validation_switched_on = config.get('defaults', {}).get('validate', True)
    config_file_req_for_cmd = not(context['command'] not in config.get(
        'defaults', {}).get('non_config_commands', []))
    # fix
    if 'kumo' in config and config_file_req_for_cmd:
        # deprecated: mograte old-style "cloudformation" entries
        fix_deprecated_kumo_config(config)

    # validate
    if validation_switched_on and 'kumo' in config and config_file_req_for_cmd:
        error = validate_tool_config(read_openapi(), config)
        if error:
            context['error'] = error


def register():
    """Please be very specific about when your plugin needs to run and why.
    E.g. run the sample stuff after at the very beginning of the lifecycle
    """
    gcdt_signals.config_read_finalized.connect(incept_defaults)
    gcdt_signals.config_validation_init.connect(fix_and_validate_config)


def deregister():
    gcdt_signals.config_read_finalized.disconnect(incept_defaults)
    gcdt_signals.config_validation_init.disconnect(fix_and_validate_config)
