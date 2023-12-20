# Awesome DevOpsSec

This repository stores various AWS and K8s security resources

## Resources

### Blogs
- [AWS 보안 점검 및 보안 설정 가이드](https://rogue-gouda-f87.notion.site/AWS-de0b5749d03b464ea2e555cba3974d0b)
- [CloudNet@ Blog](https://gasidaseo.notion.site/gasidaseo/CloudNet-Blog-c9dfa44a27ff431dafdd2edacc8a1863)
- [MR.ZERO](https://mr-zero.tistory.com/)

### Documents
> #### AWS
- [CIS Amazon Web Services Foundations Benchmark v2.0.0](https://downloads.cisecurity.org/#/)
- [AWS Foundational Security Best Practices (FSBP) standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html?fbclid=IwAR1G_Me8JWLdln5QdCbtOobzLkbG5pNtZX3RhkxXWynZa6ZIMsadtE5ZkWc_aem_th_AcNTJ4ku8j1NdTdF8W3tjUKcBGe0vWbKvIQNV3ibO00ezQaBCG8PyGYu5Tf35q8mt1s)
- [AWS Cloud Security Checklist](https://securitycipher.com/aws-security-checklist/)
- [Ultimate Guide to Incident Response in AWS](https://14518100.fs1.hubspotusercontent-na1.net/hubfs/14518100/Playbooks/Playbook_Ultimate%20Guide%20to%20Incident%20Response%20in%20AWS.pdf)
> #### Kubernetes
- [CIS Kubernetes Benchmark v1.8.0](https://downloads.cisecurity.org/#/)
- [Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [K8s Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [Securing a K8s Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)
- [EKS Best Practices Guides](https://aws.github.io/aws-eks-best-practices/)

### Articles
> #### AWS
- [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Rhino Security Labs Strategic & Technical Blog](https://rhinosecuritylabs.com/blog/?category=aws,cloud-security)
- [Detailed Analysis of CloudDon, Cloud Data Breach of Korea e-commerce company](https://medium.com/s2wblog/detailed-analysis-of-clouddon-cloud-data-breach-of-korea-e-commerce-company-948c3a5df90d)
- [How I was able to access millions of ID cards on an e-commerce platform](https://sanggiero.com/posts/how-i-was-able-to-access-millions-id-cards-e-commerce/)
> #### Kubernetes
- [K8s Standard Architecture(2024)](https://github.com/sysnet4admin/_Book_k8sInfra/blob/main/docs/k8s-stnd-arch/2024/2024-k8s-stnd-arch.pdf)

### Workshops
> #### AWS
- [AWS Well Architected Labs - Security](https://wellarchitectedlabs.com/security/)
- [AWS Security Workshops](https://awssecworkshops.com/)
- [AWS Incident Response Playbooks Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/43742d64-6a5e-45ea-9339-cbb3fb26944e/en-US)
> #### Kubernetes
- [Amazon EKS Workshops](https://awskrug.github.io/eks-workshop/)

### Conferences
- [AWS Security and Risk Management Forum 2023](https://www.awssecevents.com/ondemandtracks/)
- [Kubernetes Security Best Practices](https://www.youtube.com/watch?v=wqsUfvRyYpw&t=123s&ab_channel=CNCF%5BCloudNativeComputingFoundation%5D)

### Challenges
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- [S3 Game](http://s3game-level1.s3-website.us-east-2.amazonaws.com/level1.html)
- [The Big IAM Challenge](https://bigiamchallenge.com/challenge/1)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)

### Trannings
- [AWS Certified Security Specialty](https://www.udemy.com/course/ultimate-aws-certified-security-specialty/)
- [Certified Kubernetes Security Specialist](https://www.udemy.com/course/certified-kubernetes-security-specialist/)

### etc
- [ATT&CK](https://attack.mitre.org/#)
- [D3FEND](https://d3fend.mitre.org/)
- [RE&CT](https://atc-project.github.io/atc-react/)
<br>

## Tools
### AWS
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud Security Posture Management(CSPM) 
- [prowler](https://github.com/prowler-cloud/prowler) - Security Vulnerability Scanner
- [check_imds](https://github.com/zer0-kr/SecOpsTools/blob/main/aws/check_imds.py) - IMDSv1 Scanner
- [my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools) - List of open source tools for AWS security

### Kubernetes
- [Trivy](https://github.com/aquasecurity/trivy) - Find vulnerabilities, misconfigurations, secrets, SBOM in containers, Kubernetes
- [kube-bench](https://github.com/aquasecurity/kube-bench) - Checks whether Kubernetes is deployed according to CIS Kubernetes Benchmark 
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Hunt for security weaknesses in Kubernetes clusters
- [managed-kubernetes-auditing-toolkit](https://github.com/DataDog/managed-kubernetes-auditing-toolkit) - identifying common security issues in EKS
- [Kubescape](https://github.com/kubescape/kubescape) - Kubernetes security platform for your clusters, CI/CD pipelines, and IDE
- [Falco](https://github.com/falcosecurity/falco) - Cloud Native Runtime Security
- [Clair](https://github.com/quay/clair) - Vulnerability Static Analysis for Containers

