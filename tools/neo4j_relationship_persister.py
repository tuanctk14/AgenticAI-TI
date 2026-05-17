# -*- coding: utf-8 -*-
"""
tools/neo4j_relationship_persister.py - Persist CVE relationships to Neo4j graph database

Stores the extracted malware/campaign/threat actor relationships in Neo4j for:
- Menu 4 graph intelligence queries
- Threat actor profiling
- Attack path discovery
- Infrastructure mapping
- Temporal threat analysis
"""

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
import logging

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None

logger = logging.getLogger(__name__)


class Neo4jRelationshipPersister:
    """Manages relationship persistence to Neo4j graph database."""

    def __init__(self):
        """Initialize Neo4j connection."""
        if not NEO4J_AVAILABLE:
            logger.warning("neo4j package not installed - skipping persistence")
            self.driver = None
            return

        if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD]):
            logger.warning("Neo4j credentials not configured - skipping persistence")
            self.driver = None
            return

        try:
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASSWORD),
                connection_timeout=10
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            logger.info("Neo4j connection established")
        except Exception as e:
            logger.warning(f"Neo4j connection failed: {e}")
            self.driver = None

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()

    def create_cve_node(self, cve_dict: dict) -> bool:
        """
        Create or update CVE node in Neo4j.

        Args:
            cve_dict: CVE object with id, severity, epss_score, etc.

        Returns: True if successful, False otherwise
        """
        if not self.driver:
            return False

        try:
            cve_id = cve_dict.get("id")
            if not cve_id:
                return False

            with self.driver.session() as session:
                session.run(
                    """
                    MERGE (cve:CVE {id: $cve_id})
                    SET cve.severity = $severity,
                        cve.epss_score = $epss_score,
                        cve.description = $description,
                        cve.published = $published,
                        cve.last_modified = $last_modified,
                        cve.updated_at = timestamp()
                    """,
                    cve_id=cve_id,
                    severity=cve_dict.get("severity", "Unknown"),
                    epss_score=cve_dict.get("enrichment", {}).get("epss_score"),
                    description=cve_dict.get("description", "")[:500],
                    published=cve_dict.get("published_date"),
                    last_modified=cve_dict.get("last_modified_date"),
                )
            logger.debug(f"Created CVE node: {cve_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating CVE node: {e}")
            return False

    def create_malware_relationships(self, cve_id: str, malwares: list) -> int:
        """
        Create malware nodes and CVE→Malware relationships.

        Args:
            cve_id: CVE identifier
            malwares: List of malware objects from OpenCTI

        Returns: Number of relationships created
        """
        if not self.driver or not malwares:
            return 0

        count = 0
        try:
            with self.driver.session() as session:
                for malware in malwares:
                    malware_id = malware.get("id", malware.get("name", "Unknown"))
                    session.run(
                        """
                        MERGE (mal:Malware {id: $malware_id})
                        SET mal.name = $name,
                            mal.types = $types,
                            mal.aliases = $aliases,
                            mal.description = $description,
                            mal.updated_at = timestamp()
                        WITH mal
                        MATCH (cve:CVE {id: $cve_id})
                        MERGE (cve)-[r:EXPLOITED_BY_MALWARE]->(mal)
                        SET r.confidence = $confidence,
                            r.source = 'OpenCTI',
                            r.created_at = timestamp()
                        """,
                        malware_id=malware_id,
                        name=malware.get("name", "Unknown"),
                        types=malware.get("malware_types", []),
                        aliases=malware.get("aliases", []),
                        description=malware.get("description", "")[:500],
                        cve_id=cve_id,
                        confidence=malware.get("confidence", 0),
                    )
                    count += 1
            logger.debug(f"Created {count} malware relationships for {cve_id}")
            return count
        except Exception as e:
            logger.error(f"Error creating malware relationships: {e}")
            return count

    def create_campaign_relationships(self, cve_id: str, campaigns: list) -> int:
        """
        Create campaign nodes and CVE→Campaign relationships.

        Args:
            cve_id: CVE identifier
            campaigns: List of campaign objects from OpenCTI

        Returns: Number of relationships created
        """
        if not self.driver or not campaigns:
            return 0

        count = 0
        try:
            with self.driver.session() as session:
                for campaign in campaigns:
                    campaign_id = campaign.get("id", campaign.get("name", "Unknown"))
                    session.run(
                        """
                        MERGE (camp:Campaign {id: $campaign_id})
                        SET camp.name = $name,
                            camp.description = $description,
                            camp.created_at_opencti = $created_at,
                            camp.updated_at = timestamp()
                        WITH camp
                        MATCH (cve:CVE {id: $cve_id})
                        MERGE (cve)-[r:EXPLOITED_IN_CAMPAIGN]->(camp)
                        SET r.confidence = $confidence,
                            r.source = 'OpenCTI',
                            r.created_at = timestamp()
                        """,
                        campaign_id=campaign_id,
                        name=campaign.get("name", "Unknown"),
                        description=campaign.get("description", "")[:500],
                        created_at=campaign.get("created_at"),
                        cve_id=cve_id,
                        confidence=campaign.get("confidence", 0),
                    )
                    count += 1
            logger.debug(f"Created {count} campaign relationships for {cve_id}")
            return count
        except Exception as e:
            logger.error(f"Error creating campaign relationships: {e}")
            return count

    def create_threat_actor_relationships(self, cve_id: str, threat_actors: list) -> int:
        """
        Create threat actor nodes and CVE→ThreatActor relationships.

        Args:
            cve_id: CVE identifier
            threat_actors: List of threat actor objects from OpenCTI

        Returns: Number of relationships created
        """
        if not self.driver or not threat_actors:
            return 0

        count = 0
        try:
            with self.driver.session() as session:
                for actor in threat_actors:
                    actor_id = actor.get("id", actor.get("name", "Unknown"))
                    session.run(
                        """
                        MERGE (actor:ThreatActor {id: $actor_id})
                        SET actor.name = $name,
                            actor.aliases = $aliases,
                            actor.description = $description,
                            actor.created_at_opencti = $created_at,
                            actor.updated_at = timestamp()
                        WITH actor
                        MATCH (cve:CVE {id: $cve_id})
                        MERGE (cve)-[r:EXPLOITED_BY_ACTOR]->(actor)
                        SET r.confidence = $confidence,
                            r.source = 'OpenCTI',
                            r.created_at = timestamp()
                        """,
                        actor_id=actor_id,
                        name=actor.get("name", "Unknown"),
                        aliases=actor.get("aliases", []),
                        description=actor.get("description", "")[:500],
                        created_at=actor.get("created_at"),
                        cve_id=cve_id,
                        confidence=actor.get("confidence", 0),
                    )
                    count += 1
            logger.debug(f"Created {count} threat actor relationships for {cve_id}")
            return count
        except Exception as e:
            logger.error(f"Error creating threat actor relationships: {e}")
            return count

    def persist_cve_relationships(self, cve_dict: dict) -> dict:
        """
        Complete persistence workflow: store CVE and all relationships.

        Args:
            cve_dict: Enriched CVE object with relationships

        Returns: {
            "cve_id": "CVE-2021-44228",
            "cve_node_created": True,
            "malware_relationships": 5,
            "campaign_relationships": 14,
            "actor_relationships": 3,
            "total_persisted": 22,
            "status": "persisted"
        }
        """
        cve_id = cve_dict.get("id")
        if not cve_id:
            return {"status": "error", "error": "No CVE ID provided"}

        # Create CVE node
        cve_created = self.create_cve_node(cve_dict)

        # Get relationships
        relationships = cve_dict.get("relationships", {})
        malwares = relationships.get("malwares", [])
        campaigns = relationships.get("campaigns", [])
        actors = relationships.get("threat_actors", [])

        # Create relationships
        malware_count = self.create_malware_relationships(cve_id, malwares)
        campaign_count = self.create_campaign_relationships(cve_id, campaigns)
        actor_count = self.create_threat_actor_relationships(cve_id, actors)

        total = malware_count + campaign_count + actor_count

        logger.info(
            f"Persisted {cve_id}: "
            f"{malware_count} malware, {campaign_count} campaigns, {actor_count} actors"
        )

        return {
            "cve_id": cve_id,
            "cve_node_created": cve_created,
            "malware_relationships": malware_count,
            "campaign_relationships": campaign_count,
            "actor_relationships": actor_count,
            "total_persisted": total,
            "status": "persisted" if total > 0 else "no_relationships"
        }


def persist_cve_relationships(cve_dict: dict) -> dict:
    """
    Standalone function to persist CVE relationships to Neo4j.

    This is the main entry point for the persistence layer.

    Args:
        cve_dict: Enriched CVE object with relationships

    Returns: Persistence status
    """
    persister = Neo4jRelationshipPersister()
    try:
        result = persister.persist_cve_relationships(cve_dict)
        return result
    except Exception as e:
        logger.error(f"Persistence error: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        persister.close()
