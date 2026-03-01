<div align="center">

# 🔐 Awesome DevOpsSec

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/zer0-kr/awesome-DevOpsSec?style=social)](https://github.com/zer0-kr/awesome-DevOpsSec)

**AWS 및 Kubernetes 보안 리소스 큐레이션**

블로그, 가이드, 아티클, 워크숍, 챌린지, 도구를 한곳에 모았습니다.

</div>

<br>

---

## 목차

- [📝 블로그](#-블로그)
- [📄 가이드 & 문서](#-가이드--문서)
- [📰 아티클](#-아티클)
- [🧪 워크숍](#-워크숍)
- [🚨 취약점 DB](#-취약점-db)
- [🎤 컨퍼런스](#-컨퍼런스)
- [🏴‍☠️ 챌린지 & CTF](#️-챌린지--ctf)
- [📚 트레이닝](#-트레이닝)
- [🛠️ 도구](#️-도구)
- [🗂️ 기타](#️-기타)

---

## 📝 블로그

#### 🇰🇷 한국어

- [CloudNet@ Blog](https://gasidaseo.notion.site/gasidaseo/CloudNet-Blog-c9dfa44a27ff431dafdd2edacc8a1863) — 클라우드 네이티브 기술 블로그
- [MR.ZERO](https://mr-zero.tistory.com/) — AWS 보안 및 DevOps 블로그

#### 🇺🇸 English

- [Rhino Security Labs Blog](https://rhinosecuritylabs.com/blog/?category=aws,cloud-security) — AWS 침투 테스트 전문 블로그
- [Hacking The Cloud](https://hackingthe.cloud/) — 클라우드 공격 기법 백과사전
- [HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security) — AWS 펜테스팅 가이드

---

## 📄 가이드 & 문서

#### AWS

- [AWS 보안 점검 및 보안 설정 가이드](https://rogue-gouda-f87.notion.site/AWS-de0b5749d03b464ea2e555cba3974d0b) — 한국어 AWS 보안 점검 가이드
- [CIS AWS Foundations Benchmark v2.0.0](https://downloads.cisecurity.org/#/) — CIS 벤치마크 표준
- [AWS FSBP Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html) — AWS Security Hub 기본 보안 모범 사례
- [AWS Cloud Security Checklist](https://securitycipher.com/aws-security-checklist/) — AWS 보안 체크리스트
- [Ultimate Guide to Incident Response in AWS](https://14518100.fs1.hubspotusercontent-na1.net/hubfs/14518100/Playbooks/Playbook_Ultimate%20Guide%20to%20Incident%20Response%20in%20AWS.pdf) — AWS 사고 대응 가이드 (PDF)

#### Kubernetes

- [CIS Kubernetes Benchmark v1.8.0](https://downloads.cisecurity.org/#/) — CIS K8s 벤치마크 표준
- [Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — NSA/CISA K8s 하드닝 가이드 (PDF)
- [K8s Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) — 공식 보안 체크리스트
- [Securing a K8s Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) — 공식 클러스터 보안 가이드
- [EKS Best Practices Guides](https://aws.github.io/aws-eks-best-practices/) — AWS EKS 보안 모범 사례

---

## 📰 아티클

#### AWS

- [My AWS Pentest Methodology](https://medium.com/@MorattiSec/my-aws-pentest-methodology-14c333b7fb58) — AWS 침투 테스트 방법론
- [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) — IAM 권한 상승 기법 및 대응
- [Detailed Analysis of CloudDon](https://medium.com/s2wblog/detailed-analysis-of-clouddon-cloud-data-breach-of-korea-e-commerce-company-948c3a5df90d) — 한국 이커머스 클라우드 데이터 유출 분석
- [How I was able to access millions of ID cards](https://sanggiero.com/posts/how-i-was-able-to-access-millions-id-cards-e-commerce/) — 이커머스 플랫폼 신분증 접근 사례

#### Kubernetes

- [K8s Standard Architecture (2024)](https://github.com/sysnet4admin/_Book_k8sInfra/blob/main/docs/k8s-stnd-arch/2024/2024-k8s-stnd-arch.pdf) — 2024년 K8s 표준 아키텍처 (PDF)
- [15 Kubernetes Mistakes Side Effects Chart](https://media.licdn.com/dms/image/D5622AQEZwQUKLg0KxQ/feedshare-shrink_2048_1536/0/1692951628708) — K8s 실수 15가지 인포그래픽

---

## 🧪 워크숍

#### AWS

- [AWS WAF 공격 및 방어 실습](https://sessin.github.io/awswafhol/) — WAF 핸즈온 랩
- [AWS Well Architected Labs - Security](https://wellarchitectedlabs.com/security/) — AWS 공식 보안 실습
- [AWS Incident Response Playbooks Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/43742d64-6a5e-45ea-9339-cbb3fb26944e/en-US) — 사고 대응 플레이북 워크숍

#### Kubernetes

- [Amazon EKS Workshops](https://awskrug.github.io/eks-workshop/) — EKS 핸즈온 워크숍

---

## 🚨 취약점 DB

- [CLOUDVULNDB](https://www.cloudvulndb.org/) — 클라우드 서비스 취약점 데이터베이스
- [Public Cloud Security Breaches](https://www.breaches.cloud/) — 공개된 클라우드 보안 사고 모음
- [Cloud Security Attacks](https://github.com/CyberSecurityUP/Cloud-Security-Attacks) — 클라우드 보안 공격 기법 정리
- [aws-customer-security-incidents](https://github.com/ramimac/aws-customer-security-incidents) — AWS 고객 보안 사고 타임라인

---

## 🎤 컨퍼런스

- [AWSKRUG Security Group](https://github.com/awskrug/security-group/tree/main) — AWS 한국 사용자 그룹 보안 모임
- [AWS 리소스 허브](https://kr-resources.awscloud.com/) — AWS 한국 공식 리소스
- [Kubernetes Security Best Practices](https://www.youtube.com/watch?v=wqsUfvRyYpw) — CNCF 공식 K8s 보안 발표 (YouTube)

---

## 🏴‍☠️ 챌린지 & CTF

#### Goat 프로젝트

- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) — AWS 취약 환경 시뮬레이터
- [KubernetesGoat](https://github.com/madhuakula/kubernetes-goat) — K8s 취약 환경 시뮬레이터
- [TerraGoat](https://github.com/bridgecrewio/terragoat) — Terraform 취약 설정 모음

#### IAM

- [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) — IAM 권한 상승 실습 환경
- [The Big IAM Challenge](https://bigiamchallenge.com/challenge/1) — IAM 정책 분석 챌린지

#### 테마별 게임

- [S3 Game](http://s3game-level1.s3-website.us-east-2.amazonaws.com/level1.html) — S3 보안 게임
- [EKS Game](https://eksclustergames.com/) — EKS 클러스터 해킹 게임
- [K8s LAN Party](https://k8slanparty.com/) — K8s 네트워크 보안 게임

#### Misconfigured

- [flAWS](http://flaws.cloud/) — AWS 설정 오류 챌린지
- [flAWS2](http://flaws2.cloud/) — flAWS 시즌 2 (공격자/방어자 시점)
- [Sadcloud](https://github.com/nccgroup/sadcloud) — 의도적으로 취약한 AWS 인프라
- [Vulnmachines](https://www.vulnmachines.com/index.php) — 클라우드 취약점 실습 플랫폼
- [CI/CDon't](https://hackingthe.cloud/aws/capture_the_flag/cicdont/) — CI/CD 파이프라인 해킹 CTF

---

## 📚 트레이닝

- [AWS Certified Security Specialty](https://www.udemy.com/course/ultimate-aws-certified-security-specialty/) — Udemy AWS 보안 자격증 강의
- [Certified Kubernetes Security Specialist](https://www.youtube.com/watch?v=Jd_j2wruz6E&list=PLpbwBK0ptssx38770vYNwZEuCeGNw54CH) — CKS 무료 강의 (YouTube)

---

## 🛠️ 도구

#### AWS

| 도구 | 설명 |
|---|---|
| [prowler](https://github.com/prowler-cloud/prowler) | AWS/Azure/GCP 보안 취약점 스캐너 |
| [steampipe](https://github.com/turbot/steampipe) | API/서비스 데이터 직접 쿼리 (zero-ETL) |
| [CloudSploit](https://github.com/aquasecurity/cloudsploit) | 클라우드 보안 형상 관리 (CSPM) |
| [check_imds](https://github.com/zer0-kr/SecOpsTools/blob/main/aws/check_imds.py) | IMDSv1 사용 인스턴스 스캐너 |
| [pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS 익스플로잇 프레임워크 |
| [my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools) | AWS 보안 오픈소스 도구 모음 |

#### Kubernetes

| 도구 | 설명 |
|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | 컨테이너/K8s 취약점·설정오류·시크릿 스캐너 |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS K8s 벤치마크 준수 검사 |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | K8s 클러스터 보안 취약점 탐색 |
| [managed-kubernetes-auditing-toolkit](https://github.com/DataDog/managed-kubernetes-auditing-toolkit) | EKS 보안 감사 도구 (DataDog) |
| [Kubescape](https://github.com/kubescape/kubescape) | K8s 보안 플랫폼 (클러스터/CI·CD/IDE) |
| [Falco](https://github.com/falcosecurity/falco) | 클라우드 네이티브 런타임 보안 |
| [Clair](https://github.com/quay/clair) | 컨테이너 이미지 정적 취약점 분석 |

---

## 🗂️ 기타

- [ATT&CK](https://attack.mitre.org/) — MITRE 공격 기법 프레임워크
- [D3FEND](https://d3fend.mitre.org/) — MITRE 방어 기법 프레임워크
- [RE&CT](https://atc-project.github.io/atc-react/) — 사고 대응 프레임워크

---

## 기여하기

리소스 추가, 링크 수정, 카테고리 제안 등 어떤 기여든 환영합니다.

**PR** 또는 **Issue**로 제안해 주세요.

---

<div align="center">

**이 리스트가 도움이 되었다면 스타를 눌러주세요!**

[![Star on GitHub](https://img.shields.io/github/stars/zer0-kr/awesome-DevOpsSec?style=social)](https://github.com/zer0-kr/awesome-DevOpsSec)

</div>
