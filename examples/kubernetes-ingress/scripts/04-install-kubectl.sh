#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

if [ -n "${INSTALL}" ]; then
    wget -nv https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin
fi

certs_dir="${dir}/certs"

mkdir -p /home/vagrant/.kube/certs

cp "${certs_dir}/k8s-admin.pem" \
   "${certs_dir}/k8s-admin-key.pem" \
   "${certs_dir}/ca-k8s.pem" \
   /home/vagrant/.kube/certs

kubectl config set-cluster kubernetes \
    --certificate-authority=/home/vagrant/.kube/certs/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${kubernetes_master}:6443

kubectl config set-credentials admin \
    --client-certificate=/home/vagrant/.kube/certs/k8s-admin.pem \
    --client-key=/home/vagrant/.kube/certs/k8s-admin-key.pem \
    --embed-certs=true

kubectl config set-context default \
    --cluster=kubernetes \
    --user=admin

kubectl config use-context default

sudo cp /root/.kube/config /home/vagrant/.kube/config

sudo chmod 755 /home/vagrant/.kube/config

sudo chown vagrant.vagrant -R /home/vagrant/.kube

until kubectl get componentstatuses
do
echo "Waiting for kubectl to connect to api-server"
sleep 1s
done

kubectl get nodes
