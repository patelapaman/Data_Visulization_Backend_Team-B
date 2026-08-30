"""
Threat Intelligence Service

Handles:
- IOC lookup
- Threat intelligence search
- Threat actor lookup
- MITRE ATT&CK lookup
"""

from database.mongodb import get_database


class IntelligenceService:

    def __init__(self, database=None):
        """
        Initialize intelligence service.

        Parameters
        ----------
        database : MongoDB database, optional
        """

        self.db = database or get_database()

        self.threat_collection = (
            self.db["threat_intelligence"]
        )

        self.mitre_collection = (
            self.db["mitre"]
        )

    def get_all_intelligence(
        self,
        limit=100
    ):
        """
        Get threat intelligence records.
        """

        records = list(
            self.threat_collection.find(
                {},
                {"_id": 0}
            ).limit(limit)
        )

        return records

    def search(
        self,
        ioc=None,
        threat_id=None,
        threat_actor=None,
        threat_type=None
    ):
        """
        Search threat intelligence.
        """

        query = {}

        if ioc:
            query["ioc"] = ioc

        if threat_id:
            query["threat_id"] = threat_id

        if threat_actor:
            query["threat_actor"] = threat_actor

        if threat_type:
            query["threat_type"] = threat_type

        records = list(
            self.threat_collection.find(
                query,
                {"_id": 0}
            ).limit(100)
        )

        return records

    def get_ioc(self, ioc):
        """
        Get intelligence for a specific IOC.
        """

        if not ioc:
            return None

        record = self.threat_collection.find_one(
            {"ioc": ioc},
            {"_id": 0}
        )

        return record

    def get_threat(self, threat_id):
        """
        Get intelligence for a threat ID.
        """

        if not threat_id:
            return None

        record = self.threat_collection.find_one(
            {"threat_id": threat_id},
            {"_id": 0}
        )

        return record

    def get_threat_actor(self, threat_actor):
        """
        Get intelligence related to a threat actor.
        """

        if not threat_actor:
            return []

        records = list(
            self.threat_collection.find(
                {
                    "threat_actor": threat_actor
                },
                {
                    "_id": 0
                }
            ).limit(100)
        )

        return records

    def get_mitre_technique(
        self,
        technique_id
    ):
        """
        Get MITRE ATT&CK technique information.
        """

        if not technique_id:
            return None

        record = self.mitre_collection.find_one(
            {
                "$or": [
                    {
                        "technique_id":
                            technique_id
                    },
                    {
                        "mitre_technique":
                            technique_id
                    },
                    {
                        "id":
                            technique_id
                    }
                ]
            },
            {
                "_id": 0
            }
        )

        return record

    def enrich_event(self, event):
        """
        Enrich a security event using threat intelligence.
        """

        if not event:
            return event

        enriched_event = event.copy()

        ioc = event.get("ioc")

        if ioc:

            intelligence = self.get_ioc(ioc)

            if intelligence:

                enriched_event[
                    "threat_intelligence"
                ] = intelligence

                enriched_event[
                    "ioc_match"
                ] = True

            else:

                enriched_event[
                    "ioc_match"
                ] = False

        else:

            enriched_event[
                "ioc_match"
            ] = False

        threat_id = event.get(
            "threat_id"
        )

        if threat_id:

            threat = self.get_threat(
                threat_id
            )

            if threat:

                enriched_event[
                    "threat_information"
                ] = threat

        technique_id = event.get(
            "mitre_technique"
        )

        if technique_id:

            mitre = self.get_mitre_technique(
                technique_id
            )

            if mitre:

                enriched_event[
                    "mitre_information"
                ] = mitre

        return enriched_event