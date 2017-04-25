package com.geontech.neo4j.security;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.RelationshipType;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.factory.GraphDatabaseFactory;
import org.neo4j.graphdb.factory.GraphDatabaseSettings;

/**
 * Neo4j security key testing with edges
 * 
 * @author Kevin Vig
 */
public class EdgeSecurity {
	private static final int PROPERTIES_PER_PARENT = 5;
	private static final int NUM_SECURITY_KEYS = 200;
	private static final int NUM_PROPERTIES_TO_SEARCH = 200;
	private static final int NUM_PARENT_NODES = 100000;
	private static final int MAX_PROPERTY_VALUE = 1000;
	private static final RelationshipType PARENT_TO_PARENT = RelationshipType.withName("PARENT_TO_PARENT");
	private static final RelationshipType PARENT_TO_PROPERTY = RelationshipType.withName("HAS_PROPS");

	private GraphDatabaseService graphDb;
	private Map<String, RelationshipType> propertyRelationships;
	private List<String> securityKeys;
	private Label nodeLabel = Label.label("NODE");
	private Label propLabel = Label.label("PROPERTY");
	private Random rand = new Random();

	private EdgeSecurity(final String testDirectory, boolean initializeDb) {
		securityKeys = new ArrayList<>();
		propertyRelationships = new HashMap<>();
		graphDb = new GraphDatabaseFactory()
				.newEmbeddedDatabaseBuilder(new File(testDirectory))
				.setConfig(GraphDatabaseSettings.pagecache_memory, "2048M")
				.newGraphDatabase();
		
		createKeys(NUM_SECURITY_KEYS);
		System.out.println("Created all Security Keys");
		
		// Registers a shutdown hook for the Neo4j
		Thread dbShutdown = new Thread(() -> {graphDb.shutdown();});
		Runtime.getRuntime().addShutdownHook(dbShutdown);
		
		if (initializeDb) {
			System.out.println("Initializing Database");
			try (Transaction tx = graphDb.beginTx()) {
				// Remove all the things
				graphDb.execute("MATCH (n) DETACH DELETE n");
				tx.success();
			}
			System.out.println("Removed all nodes");
			
			try (Transaction tx = graphDb.beginTx()) {
				// Grab all the current indexes and remove them
				Result res = graphDb.execute("CALL db.indexes() YIELD description");
				res.<String>columnAs("description").stream()
				.map(str -> "DROP " + str)
				.forEach(graphDb::execute);
				tx.success();
			}
			System.out.println("Dropped all indexes");
			
			try (Transaction tx = graphDb.beginTx()) {
				// Grab all the current indexes and remove them
				for (String key : securityKeys) {
					graphDb.execute(String.format("CREATE (n:FAKE_NODE)-[:HAS_PROPS_%1$s]->(n)<-[:PARENT_TO_PARENT_%1$s]-(n)", key));
				}
				tx.success();
			}
			System.out.println("Created fake node and edges");
		}
	}

	private void createKeys(int num) {
		String key;
		for (int i = 0; i < num; ++i) {
			key = String.format("%03x", i);
			securityKeys.add(key);
			propertyRelationships.put(key, RelationshipType.withName("HAS_PROPS_" + key));
		}
	}

	private List<Node> createNodes(Label nodeLabel, int num) {
		List<Node> result = new ArrayList<>();
		try (Transaction tx = graphDb.beginTx()) {
			for (int i = 0; i < num; ++i) {
				String secKey = securityKeys.get(rand.nextInt(securityKeys.size()));
				Node n = graphDb.createNode(nodeLabel);
				n.setProperty("nodeId", String.valueOf(i));
				n.setProperty("uuid", UUID.randomUUID().toString());
				n.setProperty("securityKey", secKey);
				result.add(n);
			}
			tx.success();
		}
		return result;
	}

	private void createPropertyNode(Node sourceNode, RelationshipType relType, Label nodeLabel, String secKey, int numProps, int start) {
		try (Transaction tx = graphDb.beginTx()) {
			Node propNode = graphDb.createNode(nodeLabel);
			propNode.setProperty("uuid", UUID.randomUUID().toString());
			
			// Create each property on both the parent and the property node
			for (int i = 0; i < numProps; ++i) {
				String propName = "prop" + Integer.toString(start + i);
				String propVal = Integer.toString(rand.nextInt(MAX_PROPERTY_VALUE));
				// Create the <propName> property on the PROPERTY node
				propNode.setProperty(propName, propVal);
				propNode.setProperty(propName + "_securityKey", secKey);
				
				// Create the <propName> and also <propName>.securityKey property on the parent node
				sourceNode.setProperty(propName, propVal);
				sourceNode.setProperty(propName + "_securityKey", secKey);
			}
			// Make the generic property edge
			Relationship rel = sourceNode.createRelationshipTo(propNode, PARENT_TO_PROPERTY);
			rel.setProperty("securityKey", secKey);
			// Make the security edge
			rel = sourceNode.createRelationshipTo(propNode, relType);
			rel.setProperty("securityKey", secKey);
			
			tx.success();
		}
	}

	public void prepareForTests() {
		// Create all the NODE nodes
		List<Node> parentNodes = createNodes(nodeLabel, NUM_PARENT_NODES);
		System.out.println("Created all parent nodes");
		
		int cnt = 0;
		Set<String> keys = new HashSet<>();
		for (Node parent : parentNodes) {
			int start = 0;
			int numPropsLeft = PROPERTIES_PER_PARENT;
			int numPropNodes = rand.nextInt(PROPERTIES_PER_PARENT) + 1;
			String key;
			// For each :NODE node, create a random number of :PROPERTY nodes
			for (int i = 0; i < numPropNodes; ++i) {
				// Find an unused security key
				do {
					key = securityKeys.get(rand.nextInt(securityKeys.size()));
				} while (keys.contains(key));
				
				int propsThisTime = (i == numPropNodes - 1) ? numPropsLeft : (PROPERTIES_PER_PARENT/numPropNodes);
				createPropertyNode(parent, propertyRelationships.get(key), propLabel, key, propsThisTime, start);
				start += propsThisTime;
				numPropsLeft -= propsThisTime;
			}
			if (cnt++%2000 == 0) System.out.println("Created properties for " + cnt + " parents");
			keys.clear();
		}
		System.out.println("Created all Property nodes");
		
		// Randomly link parent nodes together
		for (Node parent : parentNodes) {
			int numPropNodes = rand.nextInt(PROPERTIES_PER_PARENT) + 1;
			try (Transaction tx = graphDb.beginTx()) {
				for (int i = 0; i < numPropNodes; ++i) {
					String secKey = securityKeys.get(rand.nextInt(securityKeys.size()));
					Node linkedNode;
					do {
						linkedNode = parentNodes.get(rand.nextInt(parentNodes.size()));
					} while (linkedNode == parent);
					
					// Make the parent->parent edge
					Relationship rel = parent.createRelationshipTo(linkedNode, PARENT_TO_PARENT);
					rel.setProperty("securityKey", secKey);
					
					// Make the security edge
					rel = parent.createRelationshipTo(linkedNode,
							RelationshipType.withName(PARENT_TO_PARENT.name() + "_" + secKey));
					rel.setProperty("securityKey", secKey);
				}
				tx.success();
			}
		}
		System.out.println("Created all Parent Node links");
		
		try (Transaction tx = graphDb.beginTx()) {
			graphDb.execute("CREATE INDEX ON :NODE(nodeId)");
			for (int i = 0; i < 5; ++i) {
				graphDb.execute("CREATE INDEX ON :NODE(prop" + i + ")");
				graphDb.execute("CREATE INDEX ON :PROPERTY(prop" + i + ")");
			}
			tx.success();
		}
		System.out.println("Created all Indexes");
	}

	public List<String> getRandomPropertyValues() {
		return IntStream.range(1, NUM_PROPERTIES_TO_SEARCH).mapToObj(i -> Integer.toString(rand.nextInt(MAX_PROPERTY_VALUE))).collect(Collectors.toList());
	}

	public List<String> getRandomSecurityKeys() {
		return securityKeys.stream().filter(key -> rand.nextBoolean()).limit(rand.nextInt(125) + 75).collect(Collectors.toList());
	}

	public void runTests() {
		List<String> keys = getRandomSecurityKeys();
		
		String securityKeyRegex = keys.stream().collect(Collectors.joining("|"));
		String nodeToNodeRels = ":PARENT_TO_PARENT_" + keys.stream().collect(Collectors.joining("|:PARENT_TO_PARENT_"));
		String propToNodeRels = ":HAS_PROPS_" + keys.stream().collect(Collectors.joining("|:HAS_PROPS_"));
		
		
		String keyInQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (n:NODE {prop0:p0})-[e:PARENT_TO_PARENT]->(n2:NODE) " +
							"WHERE n.prop0_securityKey IN {securityKeys} AND n2.prop0_securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN n2.prop0 AS prop0";
		
		String regexQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (n:NODE {prop0:p0})-[e:PARENT_TO_PARENT]->(n2:NODE) " +
							"WHERE n.prop0_securityKey =~ {securityKeys} AND n2.prop0_securityKey =~ {securityKeys} AND e.securityKey =~ {securityKeys} " +
							"RETURN n2.prop0 AS prop0";
		
		String edgeQuery  = "UNWIND {propVals} AS p0 " +
							String.format("MATCH (:PROPERTY {prop0:p0})<-[%1$s]-(:NODE)-[%2$s]->(:NODE)-[%1$s]->(p2:PROPERTY) ", propToNodeRels, nodeToNodeRels) +
							"WHERE exists(p2.prop0) " +
							"RETURN p2.prop0 AS prop0";
		
		String edgeKeyInQuery = "UNWIND {propVals} AS p0 " +
							String.format("MATCH (:PROPERTY {prop0:p0})<-[%1$s]-(:NODE)-[e:PARENT_TO_PARENT]->(n2:NODE) ", propToNodeRels) +
							"WHERE n2.prop0_securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN n2.prop0 AS prop0";
		
		String propEdgeKeyInQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (:PROPERTY {prop0:p0})<-[e1:HAS_PROPS]-(:NODE)-[e:PARENT_TO_PARENT]->(n2:NODE) " +
							"WHERE e1.securityKey IN {securityKeys} AND n2.prop0_securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN n2.prop0 AS prop0";
		
		String propKeyInQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (p:PROPERTY {prop0:p0})<-[:HAS_PROPS]-(:NODE)-[e:PARENT_TO_PARENT]->(n2:NODE) " +
							"WHERE p.prop0_securityKey IN {securityKeys} AND n2.prop0_securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN n2.prop0 AS prop0";
		
		String propKeyInBothQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (p:PROPERTY {prop0:p0})<-[:HAS_PROPS]-(:NODE)-[e:PARENT_TO_PARENT]->(:NODE)-[:HAS_PROPS]->(p2:PROPERTY) " +
							"WHERE exists(p2.prop0) AND p.prop0_securityKey IN {securityKeys} AND p2.prop0_securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN p2.prop0 AS prop0";
		
		String propEdgeKeyBothInQuery = "UNWIND {propVals} AS p0 " +
							"MATCH (:PROPERTY {prop0:p0})<-[e1:HAS_PROPS]-(:NODE)-[e:PARENT_TO_PARENT]->(:NODE)-[e2:HAS_PROPS]->(p2:PROPERTY) " +
							"WHERE exists(p2.prop0) AND e1.securityKey IN {securityKeys} AND e2.securityKey IN {securityKeys} AND e.securityKey IN {securityKeys} " +
							"RETURN p2.prop0 AS prop0";
		
//		System.out.println(keyInQuery);
//		System.out.println(regexQuery);
//		System.out.println(edgeQuery);
//		System.out.println(edgeKeyInQuery);
//		System.out.println(propEdgeKeyInQuery);
//		System.out.println(propKeyInQuery);
//		System.out.println(propKeyInBothQuery);
//		System.out.println(propEdgeKeyBothInQuery);
		
		Map<String, Object> queryProps = new HashMap<>();
		queryProps.put("propVals", getRandomPropertyValues());
		queryProps.put("securityKeys", keys);
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(keyInQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t1\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		queryProps.remove("securityKeys");
		queryProps.put("securityKeys", securityKeyRegex);
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(regexQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t2\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(edgeQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t3\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		queryProps.put("securityKeys", keys);
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(edgeKeyInQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t4\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(propEdgeKeyInQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t5\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(propKeyInQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t6\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(propKeyInBothQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t7\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		
		try (Transaction tx = graphDb.beginTx()) {
			long t1 = System.nanoTime();
			Result r = graphDb.execute(propEdgeKeyBothInQuery, queryProps);
			long t2 = System.nanoTime();
			long num = r.columnAs("prop0").stream().count();
			long t3 = System.nanoTime();
			System.out.println(String.format("%d\t%d\t8\t%d\t%d\t%d", keys.size(), num, (t2-t1)/1000000, (t3-t2)/1000000, (t3-t1)/1000000));
			tx.success();
		}
		System.out.println();
	}

	public static void main( String[] args ) {
		Options options = new Options();
		
		Option db = new Option("d", "database", true, "Neo4j database directory");
		db.setRequired(true);
		options.addOption(db);
		
		Option initialize = new Option("i", "initialize", false, "Initialize the graph - deletes everything");
		initialize.setRequired(false);
		options.addOption(initialize);
		
		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmd;
		
		try {
			cmd = parser.parse(options, args);
		} catch (ParseException e) {
			System.out.println(e.getMessage());
			formatter.printHelp("Neo4j Edge Security", options);
			System.exit(1);
			return;
		}
		
		boolean initializeDb = cmd.hasOption('i');
		EdgeSecurity edgeSec = new EdgeSecurity(cmd.getOptionValue('d'), initializeDb);
		if (initializeDb) {
			edgeSec.prepareForTests();
		}
		System.out.println("Num Security Keys\tNumber Results\tQuery #\tPlan Time(ms)\tExecute Time(ms)\tTotal Time(ms)");
		for (int i = 0; i < 10; ++i) {
			edgeSec.runTests();
		}
		System.out.println("Done running");
		System.out.println(edgeSec.securityKeys.stream().collect(Collectors.joining("|")));
		System.out.println(":PARENT_TO_PARENT_" + edgeSec.securityKeys.stream().collect(Collectors.joining("|:PARENT_TO_PARENT_")));
		System.out.println(":HAS_PROPS_" + edgeSec.securityKeys.stream().collect(Collectors.joining("|:HAS_PROPS_")));
	}
}
