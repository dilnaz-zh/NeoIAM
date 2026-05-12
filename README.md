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
#### 1. Shadow Admin Detection (Privilege Escalation)
Find users who are not in the "Admin" group but have a combination of permissions that allow them to take over the account.
+ Looks for Lambda exploitation: `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`.
```
match (u:User)-[ :HAS_POLICY|MEMBER_OF*1..2]->(:Policy)-[ :ALLOW]->( a:Action) 
where a.name in ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
with u, collect(DISTINCT a.name) as user_permisssions
where size(user_permisssions) = 3 return u.name as potentional_vulnerabale_user
```
#### 2. Search for escalation chain via Role Chaining.
A user can have these three rights not by himself, but through a role into which he can “change clothes”. 

The request still ensures that a user is considered vulnerable only if they (either themselves or through a role) collect the entire set of three actions.
```
match (u:User)-[:CAN_ASSUME_POLICY*0..1]->(principal)
where (principal:User OR principal:Role)
match (principal)-[:HAS_POLICY|MEMBER_OF*1..2]->(:Policy)-[:ALLOW]->(a:Action)
where a.name in ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
with u, collect(DISTINCT a.name) as user_permissions
where size(user_permissions) = 3
returm u.name as potential_vulnerable_user, user_permissions
```
#### 3. Privilege Escalation via Group
Often, users receive excessive rights not directly, but because they were added to a "harmless" group that has rights to modify other groups.
```
match (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_POLICY]->(:Policy)-[:ALLOW]->(a:Action) where a.name in ['iam:AddUserToGroup', 'iam:UpdateGroup'] return u.name, g.name, a.name
```
#### 4. Explosive Privilege Escalation
Demonstration of how the unintentional deletion of a single deny rule in Group Policy leads to a mass compromise (10+ accounts) by activating a latent attack vector via iam:PassRole and AWS Lambda.
+ **The logic**: Create a group and add users. Add permissions such: ALLOW - lambda (both of them) and DENY - iam:passrole. Run this query and it shows that nobody has the exsessive permissions. However, a member of this group need to run iam:PassRole, so they request to remove the DENY for iam:PassRole in the policy. Now, run the query again and you could see the privelege escalation scenario.
```
match (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_POLICY]->(pol:Policy)-[rel:ALLOW]->(a:Action)
where a.name IN ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
with u, collect(DISTINCT a.name) as user_permissions
where size(user_permissions) = 3
return u.name as vulnerable_student, user_permissions
```
#### 5. Detection of unauthorized third-party access 
In AWS, each role has an "Assume Role Policy Document." This is a list of who is allowed to log into that role. If it contains an account ID that isn't on your "whitelist," it's a critical vulnerability. The algorithm scans the AssumeRolePolicyDocument (Trust Policy) of all roles and matches the trusted party IDs against the corporate whitelist.
> [!NOTE]  
> In the `main.py` add your AWS account ID, it is written as:
> ```
> MY_ACCOUNT_ID = your_account_id 
> ```
```
match (e:ExternalAccount)-[rel:DANGEROUS_TRUST]->(r:Role) return e.id AS attacker_account, r.name AS vulnerable_role
```
#### 6. Old Access Keys
Search for active Access Keys that have not been used for more than 90 days (or are simply very old).

I used the list_access_keys method for each user. AWS returns the key creation date (CreateDate). Then I compare it with the current date and calculate the key's age in days.
```
match (u:User) where u.key_age_days > 90 return u.name AS User, u.key_age_days AS DaysOld order by u.key_age_days DESC
```

Another case - the access keys are old + _have an administarion access_ 
```
match (u:User)-[:HAS_POLICY|MEMBER_OF*1..2]->(:Policy)-[:ALLOW]->(a:Action)
where u.key_age_days > 90 AND a.name = '*' return u.name, u.key_age_days
```
#### 7. Effective Action Analysis
It demonstrates the "Deny Overrides Allow" principle of AWS IAM.
It first finds all actions that are explicitly ALLOWED for the user through her group memberships and policies. Then, it uses a WHERE NOT clause to filter out any of those actions that are also explicitly DENIED.
```
match(u:User)-[:MEMBER_OF]->(g)-[:HAS_POLICY]->(p)-[:ALLOW]->(a:Action)
where not (u)-[:MEMBER_OF]->(g)-[:HAS_POLICY]->()-[:DENY]->(a)
return a.name as effective_action
```
