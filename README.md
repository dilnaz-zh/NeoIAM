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

  ```aws configure```<br />

Provide your _**AWS Access Key ID**_, _**Secret Access Key**_ and default region.
### 2. Installation
Clone the repository and install the required Python dependencies:<br />

```git clone https://github.com/dilnaz-zh/NeoIAM.git```
### 3. Environment Configuration
Go to `.env` file, provide your Neo4j connection details and _**AWS Access Key ID**_, _**Secret Access Key**_:
```AWS_ACCESS_KEY_ID= your_access_id
   AWS_SECRET_ACCESS_KEY= your_secret_key
   NEO4J_URI= your_neo4j_uri
   NEO4J_USER= your_neo4j_username
   NEO4J_PASSWORD= your_neo4j_passwd```



