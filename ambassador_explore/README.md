# Getting Started with Ambassador

Source credit: https://www.datawire.io/envoyproxy/envoy-as-api-gateway/

kubectl apply -f ambassador-service.yaml

With RBAC: kubectl apply -f https://getambassador.io/yaml/ambassador/ambassador-rbac.yaml

W/O RBAC: kubectl apply -f https://getambassador.io/yaml/ambassador/ambassador-no-rbac.yaml

kubectl get pods

kubectl describe service ambassador

export AMBASSADORURL=X.X.X.X

curl $AMBASSADORURL/httpbin/ip/

kubectl get pods

kubectl port-forward ambassador-1378270275-51qns 8877

visiting http://localhost:8877 in your web browser

# Ambassador and Istio: Edge Proxy and Service Mesh

Source credit: https://www.getambassador.io/user-guide/with-istio, https://istio.io/docs/guides/bookinfo/

kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/kube/bookinfo.yaml)

istioctl create -f samples/bookinfo/routing/bookinfo-gateway.yaml

kubectl apply -f https://getambassador.io/yaml/ambassador/ambassador-no-rbac.yaml

kubectl apply -f ambassador-service.yaml

kubectl get svc

see the external IP assigned to our LoadBalancer OR export AMBASSADOR_IP=$(kubectl get services ambassador | tail -1 | awk '{ print $4 }')

curl 35.224.41.XX/httpbin/ip OR curl $AMBASSADOR_IP/httpbin/ip

kubectl delete ingress gateway

kubectl apply -f <(istioctl kube-inject -f ~/repo/gcp-explore/ambassador_explore/ambassador-bookinfo.yaml )






