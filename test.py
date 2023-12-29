from mitreattack.stix20 import MitreAttackData

mitre_attack_data = MitreAttackData("enterprise-attack.json")

def getTactics():
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    tactics = sorted(tactics, key=lambda x: x["external_references"][0]["external_id"])

    return tactics

def getTechniques(tactic):
    techniques = mitre_attack_data.get_techniques_by_tactic(
        tactic, "enterprise-attack", remove_revoked_deprecated=True
    )

    techniques = sorted(techniques, key=lambda x: x["external_references"][0]["external_id"])

    result_techniques = []

    for i in range(0,len(techniques)):
        id = techniques[i]["external_references"][0]["external_id"]
        if not "." in id:
            result_techniques.append(techniques[i])

    return result_techniques

def getSubtechniques(tactic, technique):
    techniques = mitre_attack_data.get_techniques_by_tactic(
        tactic, "enterprise-attack", remove_revoked_deprecated=True
    )

    techniques = sorted(techniques, key=lambda x: x["external_references"][0]["external_id"])

    result_techniques = []

    for i in range(0,len(techniques)):
        id = techniques[i]["external_references"][0]["external_id"]
        if technique+"." in id:
            result_techniques.append(techniques[i])

    return result_techniques

def getGroups():
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)

    groups = sorted(groups, key=lambda x: x["name"])

    return groups

def getGroup(name):
    groups = getGroups()

    for group in groups:
        if group["name"] == name:
            return group

    return None


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    for tactic in tactics:
        print(tactic["name"])

    techniques = mitre_attack_data.get_techniques_by_tactic(
        "defense-evasion", "enterprise-attack", remove_revoked_deprecated=True
    )

    result = {"tactic": "Defense Evasion", "techniques": {}}

    techniques = sorted(techniques, key=lambda x: x["external_references"][0]["external_id"])

    # for technique in techniques:
    #     id = technique["external_references"][0]["external_id"]

    #     if "." in id:
    #         result["techniques"][id.split(".")[0]]["sub-techniques"][id] = {"sub-technique": technique}
    #     else:
    #         result["techniques"][id] = {"technique": technique, "sub-techniques": {}}

if __name__ == "__main__":
    # techniques = getTechniques("defense-evasion")
    # for technique in techniques:
    #     print(technique["external_references"][0]["external_id"])
       
    subtechniques = getSubtechniques("defense-evasion","T1574")
    for subtechnique in subtechniques:
        print(subtechnique["external_references"][0]["external_id"]) 