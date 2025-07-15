# To setup the environment:
#
#   python3 -m ensurepip --default-pip
#   python3 -m pip install toml
#
# To run:
#
#   python3 contrib/toml-gen.py <FILE>

import re
import sys
import toml

pattern1 = r'ADD.?\(\s*"([^"]*)"\s*(?:,\s*([^)]*))?\s*\)'
pattern2 = r'if\(\s*(?:FD_(?:LIKELY|UNLIKELY)\(\s*)?!?(.*?)(?:\s*\)\s*\)|\s*\))'

flag_config_map = {}
config_type_map = {}
flag_type_map   = {}
key_config_map  = {}

def construct_config_type_map(data, prefix=None):
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            key_config_map[full_key] = key
            if isinstance(value, dict):
                config_type_map[full_key] = "dict"
                construct_config_type_map(value, full_key)
            elif isinstance(value, list):
                config_type_map[full_key] = "list"
            else:
                config_type_map[full_key] = type(value).__name__

def construct_flag_config_map(lines):
    for i in range(len(lines)):
        line  = lines[i].strip()
        match = re.search(pattern1, line)
        if match:
            flag   = match.group(1)
            config = match.group(2).strip() if match.group(2) else None
            if not config:
                if line.startswith("if"):
                    match  = re.search(pattern2, line)
                else:
                    match  = re.search(pattern2, lines[i-1].strip())
                if match:
                    config = match.group(1)
            if flag and flag not in flag_config_map:
                if config and config.startswith("config"):
                    key = config.split('->')[-1]
                    key = key.replace("frankendancer.", "")
                    if key.find('[') != -1:
                        key = key[:key.find('[')]
                    flag_config_map[flag] = key

def update_flag_config_map(lines):
    for line in lines:
        line = line.strip()
        if line.startswith("CFG_POP1") or line.startswith("CFG_POPARRAY1"):
            start = line.find('(')
            end   = line.find(')')
            args  = line[start+1:end].split(',')
            arg1, arg2, arg3 = args[0].strip(), args[1].strip(), args[2].strip()
            for key in flag_config_map:
                if arg3 == flag_config_map[key]:
                    flag_config_map[key] = arg2

def update_dict_with_value(data, full_key, data_type, value):
    parts = full_key.split('.')
    if len(parts) == 1:
        if data_type == "list":
            if parts[0] in data:
                data[parts[0]].append(value)
            else:
                data[parts[0]] = [value]
        elif data_type == "dict":
            print("this value cannot be a dict")
        else:
            if parts[0] in data:
                print("this value cannot be updated")
            else:
                data[parts[0]] = value
    else:
        if parts[0] not in data:
            data[parts[0]] = {}
        update_dict_with_value(data[parts[0]], '.'.join(parts[1:]), data_type, value)

def main():

    with open("src/app/fdctl/commands/run_agave.c", 'r') as f:
        run_agave = f.readlines()
    construct_flag_config_map(run_agave)

    with open("src/app/shared/fd_config_parse.c", 'r') as f:
        fd_config_parse = f.readlines()
    update_flag_config_map(fd_config_parse)

    default_toml = toml.load("src/app/fdctl/config/default.toml")
    construct_config_type_map(default_toml)

    for k, v in flag_config_map.items():
        for u, w in config_type_map.items():
            if u.endswith(v):
                flag_type_map[k] = w

    flags_file = sys.argv[1]
    with open(flags_file, 'r') as f:
        flags_to_parse = f.readlines()

    data = {}
    for line in flags_to_parse:
        flag, *arg = line.strip().split(' ')
        if flag not in flag_config_map:
            print(f"Cannot convert flag {flag}")
            continue
        arg = arg[0] if arg else None
        if arg is None:
            if flag.startswith('--no') or flag.startswith('--disable'):
                arg = False
            else:
                arg = True
        if flag_type_map[flag] == "int":
            arg = int(arg)
        elif flag_type_map[flag] == "float":
            arg = float(arg)
        update_dict_with_value(data, flag_config_map[flag], flag_type_map[flag], arg)

    # for key, value in flag_config_map.items():
    #     print(key, value)
    # for key, value in config_type_map.items():
    #     print(key, value)
    # for key, value in key_config_map.items():
    #     print(key, value)

    print("# Generated Firedancer TOML Config")
    print(toml.dumps(data))

if __name__ == '__main__':
    main()
