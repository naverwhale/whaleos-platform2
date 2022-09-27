#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2017 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Transforms and validates cros config from source YAML to target JSON"""

from __future__ import print_function

import argparse
import collections
import copy
import functools
import itertools
import json
import os
import re
import subprocess
import sys

import six

# pylint: disable=wrong-import-position
this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
import configfs
import libcros_schema
sys.path.pop(0)

CHROMEOS = 'chromeos'
CONFIGS = 'configs'
DEVICES = 'devices'
PRODUCTS = 'products'
SKUS = 'skus'
CONFIG = 'config'
BRAND_ELEMENTS = ['brand-code', 'firmware-signing', 'wallpaper',
                  'regulatory-label']
# External stylus is allowed for whitelabels
EXTERNAL_STYLUS = 'external'
TEMPLATE_PATTERN = re.compile('{{([^}]*)}}')

MOSYS_OUTPUT_NAME = 'config.c'


def MergeDictionaries(primary, overlay):
  """Merges the overlay dictionary onto the primary dictionary.

  If an element doesn't exist, it's added.
  If the element is a list, they are appended to each other.
  Otherwise, the overlay value takes precedent.

  Args:
    primary: Primary dictionary
    overlay: Overlay dictionary
  """
  for overlay_key in overlay.keys():
    overlay_value = overlay[overlay_key]
    if not overlay_key in primary:
      primary[overlay_key] = overlay_value
    elif isinstance(overlay_value, collections.Mapping):
      MergeDictionaries(primary[overlay_key], overlay_value)
    elif isinstance(overlay_value, list):
      primary[overlay_key].extend(overlay_value)
    else:
      primary[overlay_key] = overlay_value


def ParseArgs(argv):
  """Parse the available arguments.

  Invalid arguments or -h cause this function to print a message and exit.

  Args:
    argv: List of string arguments (excluding program name / argv[0])

  Returns:
    argparse.Namespace object containing the attributes.
  """
  parser = argparse.ArgumentParser(
      description='Validates a YAML cros-config and transforms it to JSON')
  parser.add_argument(
      '-s',
      '--schema',
      type=str,
      help='Path to the schema file used to validate the config')
  parser.add_argument(
      '-c',
      '--config',
      type=str,
      help='Path to the YAML config file that will be validated/transformed')
  parser.add_argument(
      '-m',
      '--configs',
      nargs='+',
      type=str,
      help='Path to the YAML config file(s) that will be validated/transformed')
  parser.add_argument(
      '-o',
      '--output',
      type=str,
      help='Output file that will be generated by the transform (system file)')
  parser.add_argument(
      '-g',
      '--generated_c_output_directory',
      type=str,
      help='Directory where generated C config code should be placed')
  parser.add_argument(
      '--configfs-output',
      type=str,
      help='Path to generated SquashFS filesystem for use in ChromeOS ConfigFS')
  parser.add_argument(
      '-f',
      '--filter',
      type=bool,
      default=False,
      help='Filter build specific elements from the output JSON')
  # TODO(b:185470553): this argument is being used to support the
  # Zephyr builders for proof-of-concept devices (devices which
  # normally target a CrOS EC), and can be removed once those builders
  # are no longer needed.
  parser.add_argument(
      '--zephyr-ec-configs-only',
      action='store_true',
      help=('Remove any configuration which does not specify '
            '/firmware/build-targets:zephyr-ec'))
  return parser.parse_args(argv)


def _SetTemplateVars(template_input, template_vars):
  """Builds a map of template variables by walking the input recursively.

  Args:
    template_input: A mapping object to be walked.
    template_vars: A mapping object built up while walking the template_input.
  """
  to_add = {}
  for key, val in template_input.items():
    if isinstance(val, collections.Mapping):
      _SetTemplateVars(val, template_vars)
    elif not isinstance(val, list):
      to_add[key] = val

  # Do this last so all variables from the parent scope win.
  template_vars.update(to_add)


def _GetVarTemplateValue(val, template_input, template_vars):
  """Applies the templating scheme to a single value.

  Args:
    val: The single val to evaluate.
    template_input: Input that will be updated based on the templating schema.
    template_vars: A mapping of all the variables values available.

  Returns:
    The variable value with templating applied.
  """
  for template_var in TEMPLATE_PATTERN.findall(val):
    replace_string = '{{%s}}' % template_var
    if template_var not in template_vars:
      formatted_vars = json.dumps(template_vars, sort_keys=True, indent=2)
      formatted_input = json.dumps(template_input, sort_keys=True, indent=2)
      error_vals = (template_var, val, formatted_input, formatted_vars)
      raise ValidationError("Referenced template variable '%s' doesn't "
                            "exist string '%s'.\nInput:\n %s\nVariables:\n%s" %
                            error_vals)
    var_value = template_vars[template_var]

    # This is an ugly side effect of templating with primitive values.
    # The template is a string, but the target value needs to be int.
    # This is sort of a hack for now, but if the problem gets worse, we
    # can come up with a more scaleable solution.
    #
    # Guessing this problem won't continue though beyond the use of 'sku-id'
    # since that tends to be the only strongly typed value due to its use
    # for identity detection.
    is_int = isinstance(var_value, int)
    if is_int:
      var_value = str(var_value)

    # If the caller only had one value and it was a template variable that
    # was an int, assume the caller wanted the string to be an int.
    if is_int and val == replace_string:
      val = template_vars[template_var]
    else:
      val = val.replace(replace_string, var_value)
  return val


def _ApplyTemplateVars(template_input, template_vars):
  """Evals the input and applies the templating schema using the provided vars.

  Args:
    template_input: Input that will be updated based on the templating schema.
    template_vars: A mapping of all the variables values available.
  """
  maps = []
  lists = []
  for key in template_input.keys():
    val = template_input[key]
    if isinstance(val, collections.Mapping):
      maps.append(val)
    elif isinstance(val, list):
      index = 0
      for list_val in val:
        if isinstance(list_val, collections.Mapping):
          lists.append(list_val)
        elif isinstance(list_val, six.string_types):
          val[index] = _GetVarTemplateValue(list_val, template_input,
                                            template_vars)
        index += 1
    elif isinstance(val, six.string_types):
      template_input[key] = _GetVarTemplateValue(val, template_input,
                                                 template_vars)

  # Do this last so all variables from the parent are in scope first.
  for value in maps:
    _ApplyTemplateVars(value, template_vars)

  # Object lists need their variables put in scope on a per list item basis
  for value in lists:
    list_item_vars = copy.deepcopy(template_vars)
    _SetTemplateVars(value, list_item_vars)
    while _HasTemplateVariables(list_item_vars):
      _ApplyTemplateVars(list_item_vars, list_item_vars)
    _ApplyTemplateVars(value, list_item_vars)


def _DeleteTemplateOnlyVars(template_input):
  """Deletes all variables starting with $

  Args:
    template_input: Input that will be updated based on the templating schema.
  """
  to_delete = []
  for key in template_input.keys():
    val = template_input[key]
    if isinstance(val, collections.Mapping):
      _DeleteTemplateOnlyVars(val)
    elif isinstance(val, list):
      for v in val:
        if isinstance(v, collections.Mapping):
          _DeleteTemplateOnlyVars(v)
    elif key.startswith('$'):
      to_delete.append(key)

  for key in to_delete:
    del template_input[key]


def _HasTemplateVariables(template_vars):
  """Checks if there are any unevaluated template variables.

  Args:
    template_vars: A mapping of all the variables values available.

  Returns:
    True if they are still unevaluated template variables.
  """
  for val in template_vars.values():
    if isinstance(val, six.string_types) and TEMPLATE_PATTERN.findall(val):
      return True


def TransformConfig(config, model_filter_regex=None):
  """Transforms the source config (YAML) to the target system format (JSON)

  Applies consistent transforms to covert a source YAML configuration into
  JSON output that will be used on the system by cros_config.

  Args:
    config: Config that will be transformed.
    model_filter_regex: Only returns configs that match the filter

  Returns:
    Resulting JSON output from the transform.
  """
  config_yaml = libcros_schema.LoadYaml(config)
  configs = []
  if DEVICES in config_yaml[CHROMEOS]:
    for device in config_yaml[CHROMEOS][DEVICES]:
      template_vars = {}
      for product in device.get(PRODUCTS, [{}]):
        for sku in device[SKUS]:
          # Template variables scope is config, then device, then product
          # This allows shared configs to define defaults using anchors, which
          # can then be easily overridden by the product/device scope.
          _SetTemplateVars(sku, template_vars)
          _SetTemplateVars(device, template_vars)
          _SetTemplateVars(product, template_vars)
          while _HasTemplateVariables(template_vars):
            _ApplyTemplateVars(template_vars, template_vars)
          sku_clone = copy.deepcopy(sku)
          _ApplyTemplateVars(sku_clone, template_vars)
          config = sku_clone[CONFIG]
          _DeleteTemplateOnlyVars(config)
          configs.append(config)
  else:
    configs = config_yaml[CHROMEOS][CONFIGS]

  if model_filter_regex:
    matcher = re.compile(model_filter_regex)
    configs = [
        config for config in configs if matcher.match(config['name'])
    ]

  # Drop everything except for configs since they were just used as shared
  # config in the source yaml.
  json_config = {
      CHROMEOS: {
          CONFIGS: configs,
      },
  }

  return libcros_schema.FormatJson(json_config)


def ClangFormat(text):
  cmd = [
      'clang-format',
      '-style=file',
  ]
  completed_process = subprocess.run(cmd, input=text.encode(), check=True,
                                     stdout=subprocess.PIPE)
  return completed_process.stdout.decode()


def GenerateMosysCBindings(config):
  """Generates Mosys C struct bindings

  Generates C struct bindings that can be used by mosys.

  Args:
    config: Config (transformed) that is the transform basis.
  """
  struct_format = """
    {.platform_name = "%s",
     .firmware_name_match = "%s",
     .sku_id = %s,
     .customization_id = "%s",
     .whitelabel_tag = "%s",
     .info = {.model = "%s"}}"""
  structs = []
  json_config = json.loads(config)
  for device_config in json_config[CHROMEOS][CONFIGS]:
    identity = device_config['identity']
    name = device_config['name']
    whitelabel_tag = identity.get('whitelabel-tag', '')
    customization_id = identity.get('customization-id', '')
    platform_name = identity.get('platform-name', '')
    sku_id = identity.get('sku-id', -1)

    # At most one of <device_tree_compatible_match> and <smbios-name-match>
    # should be set (depends on whether this is for ARM or x86). This is used as
    #  <firmware_name_match> for mosys.
    firmware_name_match = identity.get('device-tree-compatible-match',
                                       identity.get('smbios-name-match', ''))
    structs.append(
        struct_format % (platform_name,
                         firmware_name_match,
                         sku_id,
                         customization_id,
                         whitelabel_tag,
                         name))

  file_format = """\
/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "lib/cros_config_struct.h"

static struct config_map all_configs[] = {%s
};

const struct config_map *cros_config_get_config_map(int *num_entries) {
  *num_entries = %s;
  return &all_configs[0];
}"""

  return ClangFormat(file_format % (',\n'.join(structs), len(structs)))


def _GenerateInferredAshSwitches(device_config):
  """Generate runtime-packed ash switches into a single device config.

  Chrome switches are packed into /ui:serialized-ash-switches in the
  resultant runtime-only configuration, as a string of null-terminated
  strings.

  Args:
    device_config: transformed configuration for a single device.

  Returns:
    Config for a single device with /ui:serialized-ash-switches added.
  """
  ui_config = device_config.get('ui', {})
  ash_switches = set()
  ash_switches |= set(ui_config.get('extra-ash-flags', []))

  help_content_id = ui_config.get('help-content-id')
  if help_content_id:
    ash_switches.add('--device-help-content-id=%s' % help_content_id)

  extra_web_apps_dir = ui_config.get('apps', {}).get('extra-web-apps-dir')
  if extra_web_apps_dir:
    ash_switches.add('--extra-web-apps-dir=%s' % extra_web_apps_dir)

  demo_mode_config = device_config.get('demo-mode', {})
  for ext_type in ('highlights', 'screensaver'):
    ext_id = demo_mode_config.get('%s-extension-id' % ext_type)
    if ext_id:
      ash_switches.add('--demo-mode-%s-extension=%s' % (ext_type, ext_id))

  has_numpad = device_config.get('keyboard', {}).get('numpad')
  if has_numpad:
    ash_switches.add('--has-number-pad')

  if not ash_switches:
    return device_config

  serialized_ash_switches = ''
  for flag in sorted(ash_switches):
    serialized_ash_switches += '%s\0' % flag

  device_config = copy.deepcopy(device_config)
  device_config.setdefault('ui', {})
  device_config['ui']['serialized-ash-switches'] = serialized_ash_switches
  return device_config


def _GenerateInferredElements(json_config):
  """Generates runtime-only elements.

  These are elements which can be inferred from a config containing
  build-only elements which only appear at runtime.  For example, this
  can be used to generate an application-specific representation of an
  otherwise abstracted configuration.

  Args:
    json_config: transformed config dictionary to use.

  Returns:
    Config dictionary, with inferred elements potentially added.
  """
  configs = []
  for config in json_config[CHROMEOS][CONFIGS]:
    ui_elements = config.get('ui', {})
    if 'help-content-id' not in ui_elements:
      customization_id = config.get('identity', {}).get('customization-id')
      whitelabel_tag = config.get('identity', {}).get('whitelabel-tag')
      model_name = config.get('name')
      ui_elements['help-content-id'] = (
          customization_id or whitelabel_tag or model_name)
    config['ui'] = ui_elements
    config = _GenerateInferredAshSwitches(config)
    configs.append(config)
  return {CHROMEOS: {CONFIGS: configs}}


def FilterBuildElements(config, build_only_elements):
  """Removes build only elements from the schema.

  Removes build only elements from the schema in preparation for the
  platform, and generates any runtime-only inferred elements.

  Args:
    config: Config (transformed) that will be filtered
    build_only_elements: List of strings of paths of fields to be filtered
  """
  json_config = json.loads(config)
  json_config = _GenerateInferredElements(json_config)
  for device_config in json_config[CHROMEOS][CONFIGS]:
    _FilterBuildElements(device_config, '', build_only_elements)

  return libcros_schema.FormatJson(json_config)


def _FilterBuildElements(config, path, build_only_elements):
  """Recursively checks and removes build only elements.

  Args:
    config: Dict that will be checked.
    path: Path of elements to filter.
    build_only_elements: List of strings of paths of fields to be filtered
  """
  to_delete = []
  for key in config:
    full_path = '%s/%s' % (path, key)
    if full_path in build_only_elements:
      to_delete.append(key)
    elif isinstance(config[key], dict):
      _FilterBuildElements(config[key], full_path, build_only_elements)
  for key in to_delete:
    config.pop(key)


def FilterNonZephyrDevices(config):
  """Remove any devices which do not specify a Zephyr EC build target.

  Args:
    config: JSON-serialized configuration.

  Returns:
    JSON-serialized configuration, potentially with some configs gone.
  """
  json_config = json.loads(config)
  new_device_configs = []
  for device_config in json_config[CHROMEOS][CONFIGS]:
    build_targets = device_config.get('firmware', {}).get('build-targets', {})
    if 'zephyr-ec' in build_targets:
      new_device_configs.append(device_config)
  return libcros_schema.FormatJson({CHROMEOS: {CONFIGS: new_device_configs}})


@functools.lru_cache()
def GetValidSchemaProperties(
    schema=os.path.join(this_dir, 'cros_config_schema.yaml')):
  """Returns all valid properties from the given schema

  Iterates over the config payload for devices and returns the list of
  valid properties that could potentially be returned from
  cros_config_host or cros_config

  Args:
    schema: Source schema that contains the properties.
  """
  schema_yaml = ReadSchema(schema)
  root_path = 'properties/chromeos/properties/configs/items/properties'
  schema_node = libcros_schema.LoadYaml(schema_yaml)
  for element in root_path.split('/'):
    schema_node = schema_node[element]

  result = {}
  _GetValidSchemaProperties(schema_node, [], result)
  return result


def _GetValidSchemaProperties(schema_node, path, result):
  """Recursively finds the valid properties for a given node

  Args:
    schema_node: Single node from the schema
    path: Running path that a given node maps to
    result: Running collection of results
  """
  full_path = '/%s' % '/'.join(path)
  valid_schema_property_types = {'array', 'boolean', 'integer', 'string'}
  for key in schema_node:
    new_path = path + [key]
    node_type = schema_node[key]['type']

    if node_type == 'object':
      if 'properties' in schema_node[key]:
        _GetValidSchemaProperties(
            schema_node[key]['properties'], new_path, result)
    elif node_type in valid_schema_property_types:
      all_props = result.get(full_path, [])
      all_props.append(key)
      result[full_path] = all_props


class ValidationError(Exception):
  """Exception raised for a validation error"""


def _IdentityEq(a, b):
  """Equality function for two identity dictionaries.

  Args:
    a: An identity dictionary.
    b: Another identity dictionary.

  Returns:
    True if a is semantically equivalent to b with respect to identity
    matching, False otherwise.
  """
  union_keys = set(a) | set(b)

  # The platform-name plays no role in identity matching, so skip it
  # when considering equivalency.
  # TODO(crbug.com/1070692): Move /identity:platform-name to
  # /mosys:platform-name so we can skip this.
  union_keys.discard('platform-name')

  def _FoldValue(value):
    # Values we can get here are integers, strings, or None.  Use
    # .lower() on strings, do nothing to everything else.
    if isinstance(value, str):
      # Consider strings of differing case to be equivalent.
      return value.lower()
    return value

  for key in union_keys:
    if _FoldValue(a.get(key)) != _FoldValue(b.get(key)):
      return False
  return True


def _ValidateUniqueIdentities(json_config):
  """Verifies the identity tuple is globally unique within the config.

  Args:
    json_config: JSON config dictionary
  """
  for config in json_config['chromeos']['configs']:
    if 'identity' not in config and 'name' not in config:
      raise ValidationError(
          'Missing identity for config: %s' % str(config))

  for config_a, config_b in itertools.combinations(
      json_config['chromeos']['configs'], 2):
    if _IdentityEq(config_a['identity'], config_b['identity']):
      raise ValidationError(
          'Identities are not unique: %s and %s' % (config_a['identity'],
                                                    config_b['identity']))


def _ValidateWhitelabelBrandChangesOnly(json_config):
  """Verifies that whitelabel changes are contained to branding information.

  Args:
    json_config: JSON config dictionary
  """
  whitelabels = {}
  for config in json_config['chromeos']['configs']:
    if 'whitelabel-tag' in config.get('identity', {}):
      if 'bobba' in config['name']: # Remove after crbug.com/1036381 resolved
        continue
      name = '%s - %s' % (config['name'], config['identity'].get('sku-id', 0))
      config_list = whitelabels.get(name, [])

      wl_minus_brand = copy.deepcopy(config)
      wl_minus_brand['identity']['whitelabel-tag'] = ''

      for brand_element in BRAND_ELEMENTS:
        wl_minus_brand[brand_element] = ''

      hw_props = wl_minus_brand.get('hardware-properties', None)
      if hw_props:
        stylus = hw_props.get('stylus-category', 'none')
        if stylus == 'none' or stylus == EXTERNAL_STYLUS:
          hw_props.pop('stylus-category', None)

      # Remove /ui:help-content-id
      if 'ui' not in wl_minus_brand:
        wl_minus_brand['ui'] = {}
      wl_minus_brand['ui']['help-content-id'] = ''

      wl_minus_brand.get('arc', {}). get('build-properties', {}).pop(
          'marketing-name', None)
      wl_minus_brand.get('arc', {}). get('build-properties', {}).pop(
          'oem', None)

      config_list.append(wl_minus_brand)
      whitelabels[name] = config_list

  # whitelabels now contains a map by device name with all whitelabel
  # configs that have had their branding data stripped.
  for device_name, configs in whitelabels.items():
    base_config = configs[0]
    for compare_config in configs[1:]:
      if base_config != compare_config:
        raise ValidationError(
            'Whitelabel configs can only change branding attributes '
            'or use an external stylus for (%s).\n'
            'However, the device %s differs by other attributes.\n'
            'Example 1: %s\n'
            'Example 2: %s' % (device_name,
                               ', '.join(BRAND_ELEMENTS),
                               base_config,
                               compare_config))


def _ValidateHardwarePropertiesAreValidType(json_config):
  """Checks that all fields under hardware-properties are boolean

     Ensures that no key is added to hardware-properties that has a non-boolean
     value, because non-boolean values are unsupported by the
     hardware-properties codegen.

  Args:
    json_config: JSON config dictionary
  """
  for config in json_config['chromeos']['configs']:
    hardware_properties = config.get('hardware-properties', None)
    if hardware_properties:
      for key, value in hardware_properties.items():
        if not isinstance(value, (bool, six.string_types)):
          raise ValidationError(
              ('All configs under hardware-properties must be '
               'boolean or an enum\n'
               "However, key '{}' has value '{}'.").format(key, value))


def _ValidateSingleMosysPlatform(configs):
  """Validate that all /identity:platform-name entries are equivalent.

  Mosys is supporting only one platform per unibuild board by
  determining the platform at compile-time instead of probing from a
  platform list.  This means it is not valid for configs to have
  differing values for /identity:platform-name on the same board.

  Args:
    configs: The transformed config to be validated.
  """
  platform_names = set()
  for device in configs['chromeos']['configs']:
    platform_name = device.get('identity', {}).get('platform-name')
    if platform_name is not None:
      platform_names.add(platform_name)

  if len(platform_names) > 1:
    raise ValidationError(
        'You may not use multiple mosys platforms on the same board. '
        'You are using: %s' % ', '.join(platform_names))


def _ValidateConsistentFingerprintFirmwareROVersion(configs):
  """Validate all /fingerprint:ro-version entries.

  A given Chrome OS board can only have a single RO version for a given FPMCU
  board. See
  http://go/cros-fingerprint-firmware-branching-and-signing#single-ro-per-mcu for details.  # pylint: disable=line-too-long

  Args:
    configs: The transformed config to be validated.
  """
  expected_ro_version = collections.defaultdict(set)
  for device in configs[CHROMEOS][CONFIGS]:
    fingerprint = device.get('fingerprint')
    if fingerprint is None:
      return

    fpmcu = fingerprint.get('board')
    ro_version = fingerprint.get('ro-version')
    expected_ro_version[fpmcu].add(ro_version)

  for versions in expected_ro_version.values():
    if len(versions) != 1:
      raise ValidationError(
          'You may not use different fingerprint firmware RO versions on the '
          'same board: %s' % expected_ro_version)


def ValidateConfig(config):
  """Validates a transformed cros config for general business rules.

  Performs name uniqueness checks and any other validation that can't be
  easily performed using the schema.

  Args:
    config: Config (transformed) that will be verified.
  """
  json_config = json.loads(config)
  _ValidateUniqueIdentities(json_config)
  _ValidateWhitelabelBrandChangesOnly(json_config)
  _ValidateHardwarePropertiesAreValidType(json_config)
  _ValidateSingleMosysPlatform(json_config)
  _ValidateConsistentFingerprintFirmwareROVersion(json_config)


def MergeConfigs(configs):
  """Evaluates and merges all config files into a single configuration.

  Args:
    configs: List of source config files that will be transformed/merged.

  Returns:
    Final merged JSON result.
  """
  json_files = []
  for yaml_file in configs:
    yaml_with_imports = libcros_schema.ApplyImports(yaml_file)
    json_transformed_file = TransformConfig(yaml_with_imports)
    json_files.append(json.loads(json_transformed_file))

  result_json = json_files[0]
  for overlay_json in json_files[1:]:
    for to_merge_config in overlay_json['chromeos']['configs']:
      to_merge_identity = to_merge_config.get('identity', {})
      to_merge_name = to_merge_config.get('name', '')
      matched = False
      # Find all existing configs where there is a full/partial identity
      # match or name match and merge that config into the source.
      # If there are no matches, then append the config.
      for source_config in result_json['chromeos']['configs']:
        identity_match = False
        if to_merge_identity:
          source_identity = source_config['identity']

          # If we are missing anything from the source identity, copy
          # it into to_merge_identity before doing the comparison, as
          # missing attributes in the to_merge_identity should be
          # treated as matched.
          to_merge_identity_extended = to_merge_identity.copy()
          for key, value in source_identity.items():
            if key not in to_merge_identity_extended:
              to_merge_identity_extended[key] = value

          identity_match = _IdentityEq(source_identity,
                                       to_merge_identity_extended)
        elif to_merge_name:
          identity_match = to_merge_name == source_config.get('name', '')

        if identity_match:
          MergeDictionaries(source_config, to_merge_config)
          matched = True

      if not matched:
        result_json['chromeos']['configs'].append(to_merge_config)

  return libcros_schema.FormatJson(result_json)


def ReadSchema(schema=None):
  """Reads the schema file and evaluates all import statements.

  Args:
    schema: Schema file used to verify the config.

  Returns:
    Schema contents with imports evaluated.
  """
  if not schema:
    schema = os.path.join(this_dir, 'cros_config_schema.yaml')
  return libcros_schema.ApplyImports(schema)

def Main(schema,
         config,
         output,
         filter_build_details=False,
         gen_c_output_dir=None,
         configfs_output=None,
         configs=None,
         zephyr_ec_configs_only=False):
  """Transforms and validates a cros config file for use on the system

  Applies consistent transforms to covert a source YAML configuration into
  a JSON file that will be used on the system by cros_config.

  Verifies that the file complies with the schema verification rules and
  performs additional verification checks for config consistency.

  Args:
    schema: Schema file used to verify the config.
    config: Source config file that will be transformed/verified.
    output: Output file that will be generated by the transform.
    filter_build_details: Whether build only details should be filtered or not.
    gen_c_output_dir: Output directory for generated C config files.
    configfs_output: Output path to generated SquashFS for ConfigFS.
    configs: List of source config files that will be transformed/verified.
    zephyr_ec_configs_only: True if device configs which do not
      contain /firmware/build-targets:zephyr-ec should be removed.
  """
  # TODO(shapiroc): Remove this once we no longer need backwards compatibility
  # for single config parameters.
  if config:
    configs = [config]

  full_json_transform = MergeConfigs(configs)
  json_transform = full_json_transform

  schema_contents = ReadSchema(schema)
  libcros_schema.ValidateConfigSchema(schema_contents, json_transform)
  ValidateConfig(json_transform)
  schema_attrs = libcros_schema.GetSchemaPropertyAttrs(
      libcros_schema.LoadYaml(schema_contents))

  if zephyr_ec_configs_only:
    json_transform = FilterNonZephyrDevices(json_transform)
  if filter_build_details:
    build_only_elements = []
    for path in schema_attrs:
      if schema_attrs[path].build_only_element:
        build_only_elements.append(path)
    json_transform = FilterBuildElements(json_transform, build_only_elements)
  if output:
    with open(output, 'w') as output_stream:
      # Using print function adds proper trailing newline.
      print(json_transform, file=output_stream)
  else:
    print(json_transform)
  if gen_c_output_dir:
    with open(os.path.join(gen_c_output_dir, MOSYS_OUTPUT_NAME), 'w') \
    as output_stream:
      # Using print function adds proper trailing newline.
      print(GenerateMosysCBindings(full_json_transform), file=output_stream)
  if configfs_output:
    configfs.GenerateConfigFSData(json.loads(json_transform), configfs_output)

# The distutils generated command line wrappers will not pass us argv.
def main(argv=None):
  """Main program which parses args and runs

  Args:
    argv: List of command line arguments, if None uses sys.argv.
  """
  if argv is None:
    argv = sys.argv[1:]
  opts = ParseArgs(argv)
  Main(opts.schema, opts.config, opts.output, opts.filter,
       opts.generated_c_output_directory, opts.configfs_output, opts.configs,
       opts.zephyr_ec_configs_only)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
