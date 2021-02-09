  # Gist
  Run parset cargo test in docker
  
  # Steps
  - Build docker using docker build . 
  - Start container `docker run -it --rm Your_Image_Just_Built /bin/sh`
  - Inside docker container run the following comments
  
  ```
  cd tmp/ 
  mkdir tests
  cd tests/
  git clone https://github.com/parallaxsecond/parsec.git
  cd parsec/
  tpm_server &
  tpm2_startup -c -T mssim
  tpm2_changeauth -c owner tpm_pass
  cargo build --features "tpm-provider,direct-authenticator"
  RUST_LOG=info ./target/debug/parsec -c e2e_tests/provider_cfg/tpm/config.toml &
  cd e2e_tests/
  cargo test --features tpm-provider normal_tests
  pkill parsec
  pkill tpm_server
  ```
  
  Credit: Hugues de Valon
  
