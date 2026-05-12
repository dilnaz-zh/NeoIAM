import boto3
import json
import os
from neo4j import GraphDatabase
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

NEO4J_URI = os.getenv('NEO4J_URI')
NEO4J_USER = os.getenv('NEO4J_USER')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD')
MY_ACCOUNT_ID = your_account_id
iam_client = boto3.client('iam')
neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def clear_database(session):
    print("clearing")
    session.run("MATCH (n) DETACH DELETE n")

def process_policy(session, principal_type, principal_name, principal_arn, policy_name, policy_arn):
    try:
        policy_info = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy_info['Policy']['DefaultVersionId']
        policy_doc = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )

        statements = policy_doc['PolicyVersion']['Document'].get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get('Effect', 'Allow').upper() 
            actions = stmt.get('Action')
            resources = stmt.get('Resource', [])

            if isinstance(actions, str): actions = [actions]
            if isinstance(resources, str): resources = [resources]

            for action in actions:
            
                if action.startswith('sts:AssumeRole') or action == 'sts:*':
                    for r_arn in resources:
                        if r_arn != "*":
        
                            session.run(f"""
                                MATCH (p:{principal_type} {{arn: $p_arn}})
                                MERGE (r:Role {{arn: $r_arn}})
                                ON CREATE SET r.name = split($r_arn, '/')[-1]
                                MERGE (p)-[:CAN_ASSUME_POLICY]->(r)
                            """, p_arn=principal_arn, r_arn=r_arn)

                
                if action: 
                    session.run(f"""
                        MATCH (principal:{principal_type} {{arn: $p_arn}})
                        MERGE (pol:Policy {{name: $pol_name, arn: $pol_arn}})
                        MERGE (act:Action {{name: $action}})
                        MERGE (principal)-[:HAS_POLICY]->(pol)
                        MERGE (pol)-[:{effect}]->(act)
                    """, p_arn=principal_arn,
                         pol_name=policy_name,
                         pol_arn=policy_arn,
                         action=action)

    except Exception as e:
        print(f"Error processing policy {policy_name}: {e}")

def sync_iam_to_neo4j(session):
   
    try:    
        all_roles = iam_client.list_roles()['Roles']
        for role in all_roles: 
            role_name = role['RoleName']
            role_arn = role['Arn']
            session.run("MERGE (r:Role {name: $r_name, arn: $r_arn})", 
                        r_name=role_name, r_arn=role_arn)

            
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict): statements = [statements]

            for stmt in statements:
                principal = stmt.get('Principal', {})
                aws_principal = principal.get('AWS', [])
                if isinstance(aws_principal, str): aws_principal = [aws_principal]

                for p in aws_principal:
    
                    parts = p.split(':')
                    if len(parts) > 4:
                        acc_id = parts[4]
                        
                        if acc_id != MY_ACCOUNT_ID:
                        
                            session.run("""
                                MATCH (r:Role {arn: $r_arn})
                                MERGE (ext:ExternalAccount {id: $acc_id})
                                MERGE (ext)-[:DANGEROUS_TRUST]->(r)
                            """, r_arn=role_arn, acc_id=acc_id)
                        else:
                
                            session.run("""
                                MATCH (r:Role {arn: $r_arn})
                                MERGE (a:Account {id: $acc_id})
                                MERGE (a)-[:TRUSTS]->(r)
                            """, r_arn=role_arn, acc_id=acc_id)
        
            
          
            attached = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for pol in attached:
                process_policy(session, "Role", role_name, role_arn, pol['PolicyName'], pol['PolicyArn'])

            inline = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
            for pol_name in inline:
                doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=pol_name)['PolicyDocument']
                self_process_inline(session, "Role", role_arn, pol_name, doc)
            
    except Exception as e:
        print(f"Error in roles processing: {e}")
   

    now = datetime.now(timezone.utc)
    

    paginator = iam_client.get_paginator('list_users') 
    
    for page in paginator.paginate():
        for user_data in page['Users']:
            username = user_data['UserName']
            user_arn = user_data['Arn']
            
            try:
                print(f"Processing user: {username}")
                
            
                keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                max_age = 0
                for key in keys:
                    create_date = key['CreateDate']
                    age_days = (now - create_date).days
                    if age_days > max_age:
                        max_age = age_days
                
    
                session.run("""
                    MERGE (u:User {arn: $arn})
                    SET u.name = $name, u.key_age_days = $age
                """, name=username, arn=user_arn, age=max_age)

    
                attached = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                for pol in attached:
                    process_policy(session, "User", username, user_arn, pol['PolicyName'], pol['PolicyArn'])
                    
        
                inline = iam_client.list_user_policies(UserName=username)['PolicyNames']
                for pol_name in inline:
                    doc = iam_client.get_user_policy(UserName=username, PolicyName=pol_name)['PolicyDocument']
                    self_process_inline(session, "User", user_arn, pol_name, doc)

        
                groups = iam_client.list_groups_for_user(UserName=username)['Groups']
                for grp in groups:
                    session.run("""
                        MATCH (u:User {arn: $u_arn})
                        MERGE (g:Group {arn: $g_arn})
                        SET g.name = $g_name
                        MERGE (u)-[:MEMBER_OF]->(g)
                    """, u_arn=user_arn, g_name=grp['GroupName'], g_arn=grp['Arn'])
                    
            
                    grp_attached = iam_client.list_attached_group_policies(GroupName=grp['GroupName'])['AttachedPolicies']
                    for gp in grp_attached:
                        process_policy(session, "Group", grp['GroupName'], grp['Arn'], gp['PolicyName'], gp['PolicyArn'])
                    
                    
                    grp_inline = iam_client.list_group_policies(GroupName=grp['GroupName'])['PolicyNames']
                    for pol_name in grp_inline:
                        doc = iam_client.get_group_policy(GroupName=grp['GroupName'], PolicyName=pol_name)['PolicyDocument']
                        self_process_inline(session, "Group", grp['Arn'], pol_name, doc)
                        
            except Exception as e:
                print(f"Error processing {username}: {e}")
    print("\nDone")
   
def self_process_inline(session, principal_type, principal_arn, policy_name, policy_document):

    statements = policy_document.get('Statement', [])

    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:

        effect = stmt.get('Effect', 'Allow').upper()
        actions = stmt.get('Action')
        resources = stmt.get('Resource', [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        for action in actions:

    
            if action.startswith('sts:AssumeRole') or action == 'sts:*':

                for r_arn in resources:

                    if r_arn != "*":

                        session.run(f"""
                            MATCH (p:{principal_type} {{arn: $p_arn}})
                            MERGE (r:Role {{arn: $r_arn}})
                            ON CREATE SET r.name = split($r_arn, '/')[-1]
                            MERGE (p)-[:CAN_ASSUME_POLICY]->(r)
                        """,
                        p_arn=principal_arn,
                        r_arn=r_arn)

        
            session.run(f"""
                MATCH (p:{principal_type} {{arn: $p_arn}})
                MERGE (pol:Policy {{name: $pol_name}})
                MERGE (act:Action {{name: $action}})
                MERGE (p)-[:HAS_POLICY]->(pol)
                MERGE (pol)-[:{effect}]->(act)
            """,
            p_arn=principal_arn,
            pol_name=policy_name,
            action=action)


def main():
    try:
        with neo4j_driver.session() as session:
            clear_database(session)
            sync_iam_to_neo4j(session)
        print("\n success")
    finally:
        neo4j_driver.close()

if __name__ == "__main__":
    main()