# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Checks the version mismatches for dependencies in Cargo based repositories:
# * In parsec itself
# * Between parsec and parsec-tool
import argparse
import re
import os
import subprocess
import sys


def run_cargo_tree(path, flags=None):
    cmd = 'cargo tree'
    if flags is not None:
        cmd += ' ' + flags
    prev_dir = os.getcwd()
    os.chdir(os.path.join(path))
    return subprocess.check_output(cmd, shell=True).decode()


def run_deps_mismatcher(lines):
    pat = re.compile('([a-zA-Z]\S+)\s(v\S+)')
    deps = dict()
    for line in lines.split('\n'):
        m = pat.search(line)
        if m is not None:
            if m.group(1) in deps.keys():
                if m.group(2) not in deps[m.group(1)]:
                    deps[m.group(1)].append(m.group(2))
            else:
                deps[m.group(1)] = [m.group(2)]
    return deps


def get_deps_with_more_than_1v(deps_and_versions):
    new_dict = dict()
    for dep_name, versions in deps_and_versions.items():
        if len(versions) > 1:
            new_dict[dep_name] = versions
    return new_dict


def print_deps(deps_and_versions):
    for dep_name, versions in deps_and_versions.items():
        print(f"{dep_name:<25} {versions}")


def main(argv=[], prog_name=''):
    parser = argparse.ArgumentParser(prog='DependencyCrossmatcher',
                                     description='Checks the version mismatches for dependencies '
                                                 'in Cargo based repositories')
    parser.add_argument("-c", "--compare", action='store_true',
                        help='Check for mismatches between parsec and parsec-tool.')
    parser.add_argument('--deps_dir',
                        required=True,
                        nargs='+',
                        help='Existing directories that contain Cargo.toml for analyzing ' \
                             'dependencies. Note: when using the -c option, parsec should be ' \
                             'first of the listed directories and parsec-tool the second.')
    args = parser.parse_args()
    mismatches = dict()

    parsec_tool_flags = '--all-features -d'
    parsec_flags = '--all-features' + ' '
    parsec_flags += '--features tss-esapi/generate-bindings,cryptoki/generate-bindings -d'

    if args.compare:
        # Versions should be sorted!
        exceptions = {
            'bindgen': ['v0.66.1'],
            'cexpr': ['v0.6.0'],
        }
        parsec_repo, parsec_tool_repo = args.deps_dir
        mismatches_parsec = run_deps_mismatcher(run_cargo_tree(parsec_repo, parsec_flags))
        mismatches_parsec_tool = run_deps_mismatcher(run_cargo_tree(parsec_tool_repo,
                                                                    parsec_tool_flags)
                                                    )

        # Dependencies that are common to both parsec_repo and parsec_tool_repo repos
        common_deps = list(set(mismatches_parsec.keys()) & set(mismatches_parsec_tool.keys()))
        for dep in common_deps:
            # Symmetric difference of repos parsec_repo and parsec_tool_repo
            mistmatch = sorted(set(mismatches_parsec[dep]) ^ set(mismatches_parsec_tool[dep]))
            if len(mistmatch) > 0:
                mismatches[dep] = mistmatch
    else:
        repo_dir = args.deps_dir[0]
        if os.path.basename(repo_dir) == 'parsec':
            # Versions should be sorted!
            exceptions = {
                'base64': ['v0.13.1', 'v0.21.4'],
                'bindgen': ['v0.57.0', 'v0.66.1'],
                'bitflags': ['v1.3.2', 'v2.4.1'],
                'cexpr': ['v0.4.0', 'v0.6.0'],
                'heck': ['v0.3.3', 'v0.4.1'],
                'nom': ['v5.1.3', 'v7.1.3'],
                'shlex': ['v0.1.1', 'v1.2.0'],
                'syn': ['v1.0.109', 'v2.0.38'],
            }
            tree_flags = parsec_flags
        elif os.path.basename(repo_dir) == 'parsec-tool':
            # Versions should be sorted!
            exceptions = {
                'base64': ['v0.13.1', 'v0.21.4'],
                'bitflags': ['v1.3.2', 'v2.4.1'],
                'nom': ['v5.1.3', 'v7.1.3'],
                'syn': ['v1.0.109', 'v2.0.38'],
                'yasna': ['v0.4.0', 'v0.5.2'],
            }
            tree_flags = parsec_tool_flags

        mismatches = run_deps_mismatcher(run_cargo_tree(repo_dir, tree_flags))
        mismatches = get_deps_with_more_than_1v(mismatches)

    print('---------------------exceptions-----------------------\n\n')
    print_deps(exceptions)

    print('---------------------mistmatches----------------------\n\n')
    print_deps(mismatches)

    if not args.compare:
        repo_name = os.path.basename(args.deps_dir[0])
        errormsg = "Found dependencies version mismatches in " + repo_name
    else:
        errormsg = "Found dependencies version mismatches between parsec and parsec-tool"

    assert exceptions == mismatches, errormsg

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
