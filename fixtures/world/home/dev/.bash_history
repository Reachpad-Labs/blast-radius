cd projects/acme-api
npm run dev
git add -A && git commit -m "fix token refresh"
git push
kubectl get pods -n prod
aws s3 ls s3://acme-prod-backups/
curl -H "Authorization: Bearer CANARY-5d0c94" https://api.acme.example/v1/deploy
psql "postgresql://app@db.acme.internal:5432/prod"
docker build -t ghcr.io/acme/api:latest .
ssh deploy@prod-01
npm install @modelcontextprotocol/server-memory
