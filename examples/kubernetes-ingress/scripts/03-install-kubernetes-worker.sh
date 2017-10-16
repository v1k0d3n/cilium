#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

certs_dir="${dir}/certs"

set -e

sudo mkdir -p /opt/cni

if [ -n "${INSTALL}" ]; then
    wget -nv https://dl.k8s.io/network-plugins/cni-amd64-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz

    sudo tar -xvf cni-amd64-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz -C /opt/cni

    wget -nv https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl

    wget -nv https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubelet

    chmod +x kubelet kubectl

    sudo cp kubelet kubectl /usr/bin/
fi

# Copy cilium certificates to /var/lib/cilium
sudo mkdir -p /var/lib/cilium

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/ca-etcd.pem" \
   "${certs_dir}/etcd-cilium-key.pem" \
   "${certs_dir}/etcd-cilium.pem" \
   "${certs_dir}/k8s-cilium-key.pem" \
   "${certs_dir}/k8s-cilium.pem" \
   /var/lib/cilium

# Copy cilium certificates to /var/lib/nginx
sudo mkdir -p /var/lib/nginx

cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/k8s-nginx-key.pem" \
   "${certs_dir}/k8s-nginx.pem" \
   /var/lib/nginx

# Copy cilium certificates to /var/lib/kubelet
sudo mkdir -p /var/lib/kubelet/

hostname=$(hostname)
cp "${certs_dir}/ca-k8s.pem" \
   "${certs_dir}/ca-kubelet.pem" \
   "${certs_dir}/k8s-kubelet-${hostname}-key.pem" \
   "${certs_dir}/k8s-kubelet-${hostname}.pem" \
   "${certs_dir}/kubelet-kubelet-${hostname}.pem" \
   "${certs_dir}/kubelet-kubelet-${hostname}-key.pem" \
   /var/lib/kubelet/

# Generate etcd-config file for cilium to contact etcd
sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controllers_ips[0]}:2379
ca-file: '/var/lib/cilium/ca-etcd.pem'
key-file: '/var/lib/cilium/etcd-cilium-key.pem'
cert-file: '/var/lib/cilium/etcd-cilium.pem'
EOF

# Create dedicated kube-config file for cilium
kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/cilium/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=cilium.kubeconfig

kubectl config set-credentials cilium \
    --client-certificate=/var/lib/cilium/k8s-cilium.pem \
    --client-key=/var/lib/cilium/k8s-cilium-key.pem \
    --embed-certs=true \
    --kubeconfig=cilium.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=cilium \
    --kubeconfig=cilium.kubeconfig

kubectl config use-context default \
    --kubeconfig=cilium.kubeconfig

sudo cp ./cilium.kubeconfig /var/lib/cilium/cilium.kubeconfig


# Create dedicated kube-config file for nginx
kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/nginx/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=nginx.kubeconfig

kubectl config set-credentials nginx \
    --client-certificate=/var/lib/nginx/k8s-nginx.pem \
    --client-key=/var/lib/nginx/k8s-nginx-key.pem \
    --embed-certs=true \
    --kubeconfig=nginx.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=nginx \
    --kubeconfig=nginx.kubeconfig

kubectl config use-context default \
    --kubeconfig=nginx.kubeconfig

sudo cp ./nginx.kubeconfig /var/lib/nginx/nginx.kubeconfig


# Create dedicated kube-config file for kubelet
sudo mkdir -p /var/lib/kubelet/

kubectl config set-cluster kubernetes \
    --certificate-authority=/var/lib/kubelet/ca-k8s.pem \
    --embed-certs=true \
    --server=https://${controllers_ips[0]}:6443 \
    --kubeconfig=kubelet.kubeconfig

kubectl config set-credentials kubelet \
    --client-certificate=/var/lib/kubelet/k8s-kubelet-${hostname}.pem \
    --client-key=/var/lib/kubelet/k8s-kubelet-${hostname}-key.pem \
    --embed-certs=true \
    --kubeconfig=kubelet.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=kubelet \
    --kubeconfig=kubelet.kubeconfig

kubectl config use-context default \
    --kubeconfig=kubelet.kubeconfig

sudo cp ./kubelet.kubeconfig /var/lib/kubelet/kubelet.kubeconfig

sudo tee /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://kubernetes.io/docs/home
After=docker.service
Requires=docker.service

[Service]
# Mount BPF fs for cilium
ExecStartPre=/bin/bash -c ' \\
        if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
           /bin/mount bpffs /sys/fs/bpf -t bpf; \\
        fi'
ExecStart=/usr/bin/kubelet \\
  --allow-privileged=true \\
  --client-ca-file=/var/lib/kubelet/ca-k8s.pem \\
  --cloud-provider= \\
  --cluster-dns=${cluster_dns_ip} \\
  --cluster-domain=cluster.local \\
  --container-runtime=docker \\
  --docker=unix:///var/run/docker.sock \\
  --kubeconfig=/var/lib/kubelet/kubelet.kubeconfig \\
  --make-iptables-util-chains=false \\
  --network-plugin=cni \\
  --node-ip=${node_ip} \\
  --register-node=true \\
  --require-kubeconfig=true \\
  --serialize-image-pulls=false \\
  --tls-cert-file=/var/lib/kubelet/kubelet-kubelet-${hostname}.pem \\
  --tls-private-key-file=/var/lib/kubelet/kubelet-kubelet-${hostname}-key.pem \\
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kubelet
sudo systemctl restart kubelet

sudo systemctl status kubelet --no-pager
