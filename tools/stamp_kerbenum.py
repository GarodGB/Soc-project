import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.database import get_connection

note = (" | RESULT: NO_DETECTION_IN_EITHER (cmp 92). Server 2022 emits no "
        "4768/0x6 or 4662 for unknown-principal kerbrute enum; validated on "
        "Sysmon EID1. Both engines miss - recommend process_creation Sigma + "
        "Wazuh Sysmon-1 rule on kerbrute image/IMPHASH "
        "1CD364A9E949D5ECEBD6C614E64BC545.")
c = get_connection()
c.execute(
    "UPDATE ad_attack_tests SET false_positive_notes = "
    "COALESCE(false_positive_notes,'') || %s WHERE test_id = %s",
    (note, "AD-T1087.002-KERB-ENUM"),
)
c.commit(); c.close()
print("finding stamped")
