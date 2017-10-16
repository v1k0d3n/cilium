#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

if [ -z "${dns_probes_ips}" ]; then
    dns_probes_ips=( "127.0.0.1" "127.0.0.1" )
fi

svc_file="${dir}/../deployments/kubedns-svc.yaml"
controller_file="${dir}/../deployments/kubedns-controller.yaml"
sa_file="${dir}/../deployments/kubedns-sa.yaml"

sed "s/\$DNS_SERVER_IP/${cluster_dns_ip}/" "${svc_file}.sed" > "${svc_file}"

sed -e "s/127.0.0.1:/${dns_probes_ips[0]}:/" \
    -e "s/127.0.0.1#/${dns_probes_ips[1]}#/" \
    -e "s/\$DNS_DOMAIN/cluster.local/" \
    "${controller_file}.sed" > "${controller_file}"

kubectl delete -f "${controller_file}" 2>/dev/null || true

kubectl delete -f "${svc_file}" 2>/dev/null || true

kubectl delete -f "${sa_file}" 2>/dev/null || true

kubectl create -f "${sa_file}" || true

kubectl create -f "${svc_file}" || true

kubectl create -f "${controller_file}" || true

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods
