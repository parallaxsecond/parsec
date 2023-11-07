import argparse
import re
import os
import subprocess
import sys


def run_cargo_build(path):
    print(f"cargo build, path: {path}")
    command = f'cargo build'
    return subprocess.check_output(command, shell=True, cwd=path)


def run_cargo_update(path, dep):
    print(f"cargo update, dep: {dep}")
    command = f'cargo update --package {dep}'
    return subprocess.check_output(command, shell=True, cwd=path)


def git_toml_deps(toml_path, deps_repo_links, deps_branches):
    lines = None
    with open(toml_path, 'r') as f:
        lines = f.readlines()

    to_update = []
    output_lines = lines + ['[patch.crates-io]\n']
    for line in lines:
        for dep in deps_repo_links.keys():
            starter = dep + " ="
            if line.startswith(starter):
                to_update.append(dep)
                new_line = f'git = "{deps_repo_links[dep]}", branch = "{deps_branches[dep]}"'
                new_line = starter + ' { ' + new_line + ' }\n'
                output_lines.append(new_line)

    for updatable in to_update:
        run_cargo_update(os.path.dirname(toml_path), updatable)

    with open(toml_path, 'w') as f:
        f.writelines(output_lines)
    git_cmd = 'git diff'
    print(subprocess.check_output(git_cmd,
                                  shell=True,
                                  cwd=os.path.dirname(toml_path)).decode('utf-8'))


def main(argv=[], prog_name=''):
    parser = argparse.ArgumentParser(prog='ReleaseTracker',
                                     description='Modifies the parsec Cargo.toml files to use the '
                                                 'main branches of parallaxsecond dependencies in '
                                                 'preparation for their publishing and release')
    parser.add_argument('paths', nargs='+', help='Absolute paths to the Cargo.toml files')
    args = parser.parse_args()

    # The order is important!
    parallaxsecond_deps = {
        'psa-crypto-sys': 'rust-psa-crypto',
        'psa-crypto': 'rust-psa-crypto',
        'tss-esapi-sys': 'rust-tss-esapi',
        'tss-esapi': 'rust-tss-esapi',
        'cryptoki-sys': 'rust-cryptoki',
        'cryptoki': 'rust-cryptoki',
        'parsec-interface': 'parsec-interface-rs',
        'parsec-client': 'parsec-client-rust',
    }

    repo_links = { repo_name: f"https://github.com/parallaxsecond/{repo_folder}.git" \
                   for repo_name, repo_folder in parallaxsecond_deps.items() }

    repo_branches = { repo_name: 'main' for repo_name in parallaxsecond_deps.keys() }
    repo_branches['tss-esapi-sys'] = '7.x.y'
    repo_branches['tss-esapi'] = '7.x.y'

    for path in args.paths:
        git_toml_deps(path, repo_links, repo_branches)
        run_cargo_build(os.path.dirname(path))

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
