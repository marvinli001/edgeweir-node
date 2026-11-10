variable "ARCH" { default = "amd64" }
variable "VERSION" { default = "dev" }
variable "COMMIT" { default = "none" }
variable "DATE" { default = "unknown" }

group "default" {
  targets = ["packages", "tree", "image"]
}

target "docker-metadata-action" {}

target "native" {
  context = "."
  platforms = ["linux/${ARCH}"]
  args = { OPENRESTY_JOBS = "4" }
  cache-from = ["type=registry,ref=ghcr.io/marvinli001/edgeweir-node:buildcache-${ARCH}", "type=gha,scope=node-e2e"]
}

target "packages" {
  inherits = ["native"]
  dockerfile = "packaging/openresty/Dockerfile"
  target = "packages"
  output = ["type=local,dest=out/openresty/.${ARCH}/packages"]
}

target "tree" {
  inherits = ["native"]
  dockerfile = "packaging/openresty/Dockerfile"
  target = "tree"
  output = ["type=local,dest=out/openresty/.${ARCH}/tree"]
}

target "image" {
  inherits = ["native", "docker-metadata-action"]
  dockerfile = "Dockerfile"
  tags = []
  cache-to = ["type=registry,ref=ghcr.io/marvinli001/edgeweir-node:buildcache-${ARCH},mode=max,image-manifest=true,oci-mediatypes=true"]
  args = {
    VERSION = VERSION
    COMMIT = COMMIT
    DATE = DATE
    IPINFO_REQUIRED = "1"
  }
  secret = ["id=ipinfo_token,env=IPINFO_TOKEN"]
  attest = ["type=provenance,mode=max", "type=sbom"]
}
