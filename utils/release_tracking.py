import argparse
import re
import os
import subprocess
import sys


def run_cargo_build(path):
    print(f"cargo build, path: {path}")
    command = f'cargo build'
    subprocess.check_output(command.split(), cwd=path)


def clone_repo(clone_dir, repo_name, branch):
    git_repo = f"https://github.com/parallaxsecond/{repo_name}.git"
    future_repo_dir = os.path.join(clone_dir, repo_name)
    if not os.path.isdir(future_repo_dir):
        command = f"git clone {git_repo} -b {branch} {future_repo_dir}"
        subprocess.check_output(command.split())
        command = f"git submodule update --init"
        subprocess.check_output(command.split(), cwd=future_repo_dir)


def git_toml_deps(toml_path, updatable_deps, deps_repos):
    lines = None
    with open(toml_path, 'r') as f:
        lines = f.readlines()

    for i in range(len(lines)):
        line = lines[i]
        for dep in updatable_deps.keys():
            if line.startswith(dep + " ="):
                # All occurences
                line = line.replace("'", '"')
                if "{" not in line:
                    # First occurence
                    line = line.replace('"', '{ version = "', 1)
                    line = line.rstrip() + ' }\n'

                if 'path' not in line:
                    line = re.sub(r'version = "[0-9\.]+"', f'path = "{deps_repos[dep]}"', line)
                lines[i] = line

                dirname = os.path.relpath('.')

    with open(toml_path, 'w') as f:
        f.writelines(lines)
    print(subprocess.check_output(['git', 'diff'], cwd=os.path.dirname(toml_path)).decode('utf-8'))


def main(argv=[], prog_name=''):
    parser = argparse.ArgumentParser(prog='ReleaseTracker',
                                     description='Modifies the parsec Cargo.toml files to use the '
                                                 'main branches of parallaxsecond dependencies in '
                                                 'preparation for their publishing and release')
    parser.add_argument('--clone_dir',
                        required=True,
                        help='Existing directory into which repositories should be cloned')
    parser.add_argument('paths', nargs='+', help='Paths to Cargo.toml files to be modified')
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

    repo_paths = { repo_name: f'{args.clone_dir}/{repo_folder}/{repo_name}' \
                   for repo_name, repo_folder in parallaxsecond_deps.items() }
    repo_paths['parsec-interface'] = f'{args.clone_dir}/parsec-interface-rs'
    repo_paths['parsec-client'] = f'{args.clone_dir}/parsec-client-rust'

    repo_branches = { repo_name: 'main' for repo_name in parallaxsecond_deps.keys() }
    repo_branches['tss-esapi-sys'] = '7.x.y'
    repo_branches['tss-esapi'] = '7.x.y'

    for repo_name, repo_folder in parallaxsecond_deps.items():
        clone_repo(args.clone_dir, repo_folder, repo_branches[repo_name])
        toml_path = os.path.join(repo_paths[repo_name], 'Cargo.toml')
        git_toml_deps(toml_path, parallaxsecond_deps, repo_paths)

    for repo_path in repo_paths.values():
        run_cargo_build(repo_path)

    for path in args.paths:
        git_toml_deps(path, parallaxsecond_deps, repo_paths)
        run_cargo_build(os.path.dirname(path))

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], sys.argv[0]))
