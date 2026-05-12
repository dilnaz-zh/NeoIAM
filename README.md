# NeoIAM
A tool for analyzing and visualizing AWS IAM configurations using the Neo4j graph database. The project allows you to identify hidden administrative privileges (Shadow Admins), analyze trust chains between accounts, and detect critical security policy errors, such as missing explicit denies for dangerous actions.
## Getting Started 
#### 1. Prerequisites
Before running the tool, ensure you have the following accounts and software ready:<br />
**Neo4j Database**<br />
You can use either the desktop version or the cloud-based sandbox:<br />
+ [Neo4j Desktop](https://neo4j.com/download/) - best for local development and deep graph exploration. Download, install, and create a new project with a local database.
+ [Neo4j Aura DB](https://neo4j.com/product/auradb/) - fully managed cloud instance. Use the free tier to host your graph in the cloid without installation.
**AWS Access**<br />
The script requires read-only access to your AWS IAM infrastructure.<br />
