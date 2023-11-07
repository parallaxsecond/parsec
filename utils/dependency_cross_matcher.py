import argparse
import re
import os
import subprocess
import sys


def run_cargo_tree(path):
    cmd = 'cargo tree --all-features '
    cmd += '--features tss-esapi/generate-bindings,cryptoki/generate-bindings -d'
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
    parser.add_argument('--deps_dir',
                        required=True,
                        help='Existing directory that contains the Cargo.toml for analyzing'
                             'dependencies')
    args = parser.parse_args()

    mismatches = run_deps_mismatcher(run_cargo_tree(args.deps_dir))
    print_deps(mismatches)

    mismatches = get_deps_with_more_than_1v(mismatches)

    print('---------------------mistmatches----------------------\n\n')
    print_deps(mismatches)

    exceptions = {
        'base64': ['v0.13.1', 'v0.21.4'],
        'bindgen': ['v0.57.0', 'v0.66.1'],
        'bitflags': ['v1.3.2', 'v2.4.0'],
        'cexpr': ['v0.4.0', 'v0.6.0'],
        'nom': ['v5.1.3', 'v7.1.3'],
        'shlex': ['v0.1.1', 'v1.2.0'],
        'syn': ['v1.0.109', 'v2.0.38'],
    }

    if exceptions != mismatches:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
