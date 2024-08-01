# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

schema = 1
artifacts {
  zip = [
    "vault-benchmark_${version}_darwin_amd64.zip",
    "vault-benchmark_${version}_darwin_arm64.zip",
    "vault-benchmark_${version}_freebsd_386.zip",
    "vault-benchmark_${version}_freebsd_amd64.zip",
    "vault-benchmark_${version}_freebsd_arm.zip",
    "vault-benchmark_${version}_linux_386.zip",
    "vault-benchmark_${version}_linux_amd64.zip",
    "vault-benchmark_${version}_linux_arm.zip",
    "vault-benchmark_${version}_linux_arm64.zip",
    "vault-benchmark_${version}_netbsd_386.zip",
    "vault-benchmark_${version}_netbsd_amd64.zip",
    "vault-benchmark_${version}_netbsd_arm.zip",
    "vault-benchmark_${version}_openbsd_386.zip",
    "vault-benchmark_${version}_openbsd_amd64.zip",
    "vault-benchmark_${version}_openbsd_arm.zip",
    "vault-benchmark_${version}_solaris_amd64.zip",
    "vault-benchmark_${version}_windows_386.zip",
    "vault-benchmark_${version}_windows_amd64.zip",
  ]
  rpm = [
    "vault-benchmark-${version_linux}-1.aarch64.rpm",
    "vault-benchmark-${version_linux}-1.armv7hl.rpm",
    "vault-benchmark-${version_linux}-1.i386.rpm",
    "vault-benchmark-${version_linux}-1.x86_64.rpm",
  ]
  deb = [
    "vault-benchmark_${version_linux}-1_amd64.deb",
    "vault-benchmark_${version_linux}-1_arm64.deb",
    "vault-benchmark_${version_linux}-1_armhf.deb",
    "vault-benchmark_${version_linux}-1_i386.deb",
  ]
  container = [
    "vault-benchmark_release-default_linux_386_${version}_${commit_sha}.docker.dev.tar",
    "vault-benchmark_release-default_linux_386_${version}_${commit_sha}.docker.tar",
    "vault-benchmark_release-default_linux_amd64_${version}_${commit_sha}.docker.dev.tar",
    "vault-benchmark_release-default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-benchmark_release-default_linux_arm64_${version}_${commit_sha}.docker.dev.tar",
    "vault-benchmark_release-default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-benchmark_release-default_linux_arm_${version}_${commit_sha}.docker.dev.tar",
    "vault-benchmark_release-default_linux_arm_${version}_${commit_sha}.docker.tar",
  ]
}
