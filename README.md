# NeoIAM
A tool for analyzing and visualizing AWS IAM configurations using the Neo4j graph database. The project allows you to identify hidden administrative privileges (Shadow Admins), analyze trust chains between accounts, and detect critical security policy errors, such as missing explicit denies for dangerous actions.
## Getting Started 
### 1. Prerequisites
Before running the tool, ensure you have the following accounts and software ready:<br />
#### Neo4j Database
You can use either the desktop version or the cloud-based sandbox:<br />
+ [Neo4j Desktop](https://neo4j.com/download/) - best for local development and deep graph exploration. Download, install, and create a new project with a local database.
  
+ [Neo4j Aura DB](https://neo4j.com/product/auradb/) - fully managed cloud instance. Use the free tier to host your graph in the cloid without installation.
#### AWS Access
The script requires read-only access to your AWS IAM infrastructure.
+ IAM Permissions: Ensure your IAM user has `IAMReadOnlyAccess` and `SecurityAudit` policies attached.
  
+ [AWS](https://aws.amazon.com/cli/): Sigh in to console and configure your credentials.<br />

  ```aws configure```

Provide your _**AWS Access Key ID**_, _**Secret Access Key**_ and default region.
### 2. Installation
Clone the repository and install the required Python dependencies:<br />

```git clone https://github.com/dilnaz-zh/NeoIAM.git```
### 3. Environment Configuration
Go to `.env` file, provide your Neo4j connection details and _**AWS Access Key ID**_, _**Secret Access Key**_:
### 4. Investigation & Threat Hunting Scenarios
In this section, I provide Cypher queries to detect common AWS misconfigurations and potential attack paths.
#### 1. Shadow Admin Detection (Privilege Escalation)</summary>
Find users who are not in the "Admin" group but have a combination of permissions that allow them to take over the account.
+ Looks for Lambda exploitation: `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`<br />

```
match (u:User)-[ :HAS_POLICY|MEMBER_OF*1..2]->(:Policy)-[ :ALLOW]->( a:Action) 
where a.name in ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
with u, collect(DISTINCT a.name) as user_permisssions
where size(user_permisssions) = 3 return u.name as potentional_vulnerabale_user ```

  



