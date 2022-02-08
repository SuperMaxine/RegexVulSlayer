package regex;

import javafx.util.Pair;
import redos.regex.Pattern4Search;
import redos.regex.redosPattern;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * @author SuperMaxine
 */
public class Analyzer {
    private static final Pattern DotP = Pattern.compile(".");
    private static final Pattern BoundP = Pattern.compile("\\b");
    private static final Pattern SpaceP = Pattern.compile("\\s");
    private static final Pattern noneSpaceP = Pattern.compile("\\S");
    private static final Pattern wordP = Pattern.compile("\\w");
    private static final Pattern AllP = Pattern.compile("[\\s\\S]");
    private static final Pattern noneWordP = Pattern.compile("\\W");

    // private final boolean OneCouting = true;
    private final boolean OneCouting = false;
    // private final boolean POA = true;
    private final boolean POA = false;
    private final boolean SLQ = true;
    // private final boolean SLQ = false;

    // private final boolean debugPath = true;
    private final boolean debugPath = false;

    // private final boolean debugStep = true;
    private final boolean debugStep = false;

    // private final boolean debugRegex = true;
    private final boolean debugRegex = false;

    private final boolean debugStuck = true;
    // private final boolean debugStuck = false;

    private final boolean realTest = true;
    // private final boolean realTest = false;

    String regex;
    int maxLength;
    private Set<Integer> fullSmallCharSet;
    private Map<Pattern.Node, Set<Integer>> bigCharSetMap;
    private final Pattern4Search testPattern;
    private final redosPattern testPattern4Search;
    public boolean attackable = false;
    public String attackMsg = "";

    // 建立FinalTree所需的全局变量
    Pattern.Node lastNode;
    private Map<Integer, Integer> groupIndex2LocalIndex; // GroupHead内的标号是localIndex递增，但BackRef所使用的是groupIndex，在GroupTail中可以拿到localIndex和groupIndex的对应
    private Map<Integer, LeafNode> groupStartNodesMap; // 以localIndex为索引，记录了所有group开始的节点
    private ArrayList<LeafNode> backRefNodes; // 存储所有反向引用的节点，用于后续以实际捕获组的copy替换
    ArrayList<LeafNode> lookaroundAtLast; // 存储从末尾向前数在遇到"实际字符"前的所有lookaround，用于提取内容或删除后在末尾添加[\s\S]*

    // 生成路径需要的结构
    LeafNode root;
    private ArrayList<LeafNode> countingNodes;
    private Map<LeafNode, ArrayList<ArrayList<Set<Integer>>>> countingPrePaths;
    private Map<LeafNode, String> countingPreRegex;
    private int id;
    private Map<Integer, Set<Integer>> id2childNodes;

    public Analyzer(String regex, int maxLength, int id) {
        this.regex = regex;
        this.maxLength = maxLength;
        fullSmallCharSet = new HashSet<>();
        bigCharSetMap = new HashMap<>();
        testPattern = Pattern4Search.compile(regex);
        testPattern4Search = redosPattern.compile(regex);

        groupIndex2LocalIndex = new HashMap<>();
        groupStartNodesMap = new HashMap<>();
        backRefNodes = new ArrayList<>();
        lookaroundAtLast = new ArrayList<>();

        countingNodes = new ArrayList<>();
        countingPrePaths = new HashMap<>();
        countingPreRegex = new HashMap<>();
        id2childNodes = new HashMap<>();

        // 记录开始时间
        long startTime = System.currentTimeMillis();
        //  建立原始树
        Pattern rawPattern = Pattern.compile(regex);
        root = buildTree(rawPattern.root, new HashSet<>());
        // System.out.println("flowchart TD");
        // printTree(root, true);
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return;
        }
        // 对原始树进行优化，生成新树
        root = buildFinalTree(root);
        // 生成所有字符集，生成字符集只改变了Pattern.Node的charSet，并没有改变tree中LeafNode的path，还需注意
        Pattern p  = Pattern.compile("[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\\\"#$%&'()*+,-./:;<=>?@\\[\\]^_`{|}~ \\t\\n\\r]");
        generateFullSmallCharSet((Pattern.CharProperty) p.root.next);
        generateAllBigCharSet();
        // System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        // printTree(root, true);
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return;
        }
        // 对新树生成所有路径
        // 生成路径操作一定要在确认所有字符集都生成完毕之后再进行
        generateAllPath(root, false);
        System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        printTree(root, true);
        // 记录结束时间
        long endTime = System.currentTimeMillis();
        System.out.println("id:"+id+",Build tree cost time: " + (endTime - startTime) + "ms");


        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            if (debugPath) {
                try {
                    attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString("generate all path time out".getBytes("utf-8"));
                    BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                    writer.write(id + "," + attackMsg + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return;
        }

        // --------------------生成树阶段结束，对漏洞进行攻击阶段开始-----------------------------

        // 生成前缀路径
        for (LeafNode node : countingNodes) {
            if(Thread.currentThread().isInterrupted()){
                System.out.println("线程请求中断...");
                if (debugPath) {
                    try {
                        attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString("generate all pre path time out".getBytes("utf-8"));
                        BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                        writer.write(id + "," + attackMsg + "\n");
                        writer.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return;
            }
            ArrayList<ArrayList<Set<Integer>>> prePaths = generatePrePath(node);
            String preRegex = generatePreRegex(node);
            Collections.sort((prePaths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
            countingPrePaths.put(node, prePaths);
            countingPreRegex.put(node, preRegex);
            // System.out.println("id: " + node.id + " preRegex: " + preRegex);
            // System.out.println("\n" + node.toString());
            // System.out.println(printPaths(prePaths, false));
            // Enumerator pre = new Enumerator(prePaths.get(0));
            // while(pre.hasNext()) {
            //     System.out.println(pre.next());
            // }
        }


        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            if (debugPath) {
                try {
                    attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString("generate all pre path time out".getBytes("utf-8"));
                    BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                    writer.write(id + "," + attackMsg + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return;
        }

        if (OneCouting) {
            for (LeafNode node : countingNodes) {
                for (int i = 0 ; i < node.paths.size() && !Thread.currentThread().isInterrupted(); i++) {
                    for (int j = i + 1; j < node.paths.size() && !Thread.currentThread().isInterrupted(); j++) {
                        ArrayList<Set<Integer>> pumpPath = getPathCompletelyOverLap(node.paths.get(i), node.paths.get(j));
                        if(pumpPath.size() != 0) {
                            for (ArrayList<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                if(Thread.currentThread().isInterrupted()){
                                    System.out.println("线程请求中断...");
                                    return;
                                }
                                Enumerator preEnum = new Enumerator(prePath);
                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                if (dynamicValidate(preEnum, pumpEnum, VulType.OneCounting)) return;
                            }
                        }
                    }
                }
            }
            System.out.println("[*] OneCouting finished");
        }

        if (POA) {
            for (int i = 0; i < countingNodes.size() && !Thread.currentThread().isInterrupted(); i++) {
                for (int j = i + 1; j < countingNodes.size() && !Thread.currentThread().isInterrupted(); j++) {
                    if (debugPath) attackMsg += "----------------------------------------------------------\nnode1(id:"+countingNodes.get(i).id+") regex:\n"+countingNodes.get(i).SelfRegex+"\nnode2(id:"+countingNodes.get(j).id+") regex:\n"+countingNodes.get(j).SelfRegex+"\n";
                    // 判断嵌套、直接相邻，以及夹着内容相邻
                    // 嵌套结构跳过不测
                    if (isNode1ChildOfNode2(countingNodes.get(i), countingNodes.get(j)) || isNode1ChildOfNode2(countingNodes.get(j), countingNodes.get(i))) {
                        continue;
                    }
                    else {
                        if (debugStuck) System.out.println("node1: " + countingNodes.get(i).id + " node2: " + countingNodes.get(j).id);
                        // 找到两者的公共父节点，然后求出两者之间夹着的路径
                        Pair<ArrayList<ArrayList<Set<Integer>>>, LeafNode> midPathsAndFrontNode = getMidAndFrontNode(countingNodes.get(i), countingNodes.get(j));

                        // LeafNode node1 = countingNodes.get(i);
                        // LeafNode node2 = countingNodes.get(j);
                        // ArrayList<ArrayList<Set<Integer>>> debugMidPaths = midPathsAndFrontNode.getKey();

                        if (midPathsAndFrontNode.getKey().size() == 0) {
                            // 说明两者直接相邻
                            if (debugPath) attackMsg += "POA-Direct Adjacent:\nnode1 paths\n" + printPaths(countingNodes.get(i).paths, false) + "\nnode2 paths\n" + printPaths(countingNodes.get(j).paths, false) + "\n\n";
                            for (ArrayList<Set<Integer>> path1 : countingNodes.get(i).paths) {
                                for (ArrayList<Set<Integer>> path2 : countingNodes.get(j).paths) {
                                    if(Thread.currentThread().isInterrupted()){
                                        System.out.println("线程请求中断...");
                                        if (debugPath) {
                                            try {
                                                attackMsg += "\nTraversing paths time out\n";
                                                attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                                            } catch (UnsupportedEncodingException e) {
                                                e.printStackTrace();
                                            }
                                            try {
                                                BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                                                writer.write(id + "," + attackMsg + "\n");
                                                writer.close();
                                            } catch (IOException e) {
                                                e.printStackTrace();
                                            }
                                        }
                                        return;
                                    }
                                    ArrayList<Set<Integer>> pumpPath = getPathCompletelyOverLap(path1, path2);
                                    if (pumpPath.size() != 0) {
                                        if (debugPath) attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(countingPrePaths.get(midPathsAndFrontNode.getValue()), false) + "\n";
                                        if (realTest) {
                                            for (ArrayList<Set<Integer>> prePath : countingPrePaths.get(midPathsAndFrontNode.getValue())) {
                                                if (Thread.currentThread().isInterrupted()) {
                                                    System.out.println("线程请求中断...");
                                                    return;
                                                }
                                                Enumerator preEnum = new Enumerator(prePath);
                                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                                if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            // 说明两者之间夹着内容，\w+0\d+
                            ArrayList<ArrayList<Set<Integer>>> prePaths = countingPrePaths.get(midPathsAndFrontNode.getValue());
                            ArrayList<Set<Integer>> pumpPath;
                            LeafNode frontNode = midPathsAndFrontNode.getValue();
                            LeafNode backNode = countingNodes.get(i) == midPathsAndFrontNode.getValue() ? countingNodes.get(j) : countingNodes.get(i);

                            if (debugPath) attackMsg += "POA-Nested:\nnode1 paths\n" + printPaths(countingNodes.get(i).paths, false) + "\nmidPaths:\n" + printPaths(midPathsAndFrontNode.getKey(), false) + "\nnode2 paths\n" + printPaths(countingNodes.get(j).paths, false)  + "\n";

                            // \w+0 vs \d+
                            for (ArrayList<Set<Integer>> path1 : splicePath(frontNode.paths, midPathsAndFrontNode.getKey())) {
                                for (ArrayList<Set<Integer>> path2 : backNode.paths) {
                                    if(Thread.currentThread().isInterrupted()){
                                        System.out.println("线程请求中断...");
                                        if (debugPath) {
                                            try {
                                                attackMsg += "\nTraversing paths time out\n";
                                                attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                                            } catch (UnsupportedEncodingException e) {
                                                e.printStackTrace();
                                            }
                                            try {
                                                BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                                                writer.write(id + "," + attackMsg + "\n");
                                                writer.close();
                                            } catch (IOException e) {
                                                e.printStackTrace();
                                            }
                                        }
                                        return;
                                    }
                                    pumpPath = getPathCompletelyOverLap(path1, path2);
                                    if (pumpPath.size() != 0) {
                                        if (debugPath) attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(prePaths, false) + "\n";
                                        if (realTest) {
                                            for (ArrayList<Set<Integer>> prePath : prePaths) {
                                                if(Thread.currentThread().isInterrupted()){
                                                    System.out.println("线程请求中断...");
                                                    return;
                                                }
                                                Enumerator preEnum = new Enumerator(prePath);
                                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                                if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) return;
                                            }
                                        }
                                    }
                                }
                            }

                            // \w+ vs 0\d+
                            for (ArrayList<Set<Integer>> path1 : splicePath(midPathsAndFrontNode.getKey(), backNode.paths)) {
                                for (ArrayList<Set<Integer>> path2 : frontNode.paths) {
                                    if(Thread.currentThread().isInterrupted()){
                                        System.out.println("线程请求中断...");
                                        if (debugPath) {
                                            try {
                                                attackMsg += "\nTraversing paths time out\n";
                                                attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                                            } catch (UnsupportedEncodingException e) {
                                                e.printStackTrace();
                                            }
                                            try {
                                                BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                                                writer.write(id + "," + attackMsg + "\n");
                                                writer.close();
                                            } catch (IOException e) {
                                                e.printStackTrace();
                                            }
                                        }
                                        return;
                                    }
                                    pumpPath = getPathCompletelyOverLap(path1, path2);
                                    if (pumpPath.size() != 0) {
                                        if (debugPath) attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(prePaths, false) + "\n";
                                        if (realTest) {
                                            for (ArrayList<Set<Integer>> prePath : prePaths) {
                                                if(Thread.currentThread().isInterrupted()){
                                                    System.out.println("线程请求中断...");
                                                    return;
                                                }
                                                Enumerator preEnum = new Enumerator(prePath);
                                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                                if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (Thread.currentThread().isInterrupted()) {
            System.out.println("线程请求中断...");
            if (debugPath) {
                try {
                    attackMsg += "\nTraversing paths time out\n";
                    attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
                try {
                    BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                    writer.write(id + "," + attackMsg + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return;
        }

        if (SLQ) {
            Enumerator preEnum = new Enumerator(new ArrayList<>());
            for (LeafNode node : countingNodes) {
                if (debugStuck) System.out.println("node: " + node.id + ",regex:" + node.SelfRegex);
                if(Thread.currentThread().isInterrupted()){
                    System.out.println("线程请求中断...");
                    if (debugPath) {
                        try {
                            attackMsg += "\nTraversing paths time out\n";
                            attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                        try {
                            BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                            writer.write(id + "," + attackMsg + "\n");
                            writer.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    return;
                }
                // 如果cmax小于100或后缀可空，则不需要检查
                if (((LoopNode) node).cmax < 100 || !neverhaveEmptySuffix(node)) continue;
                // SLQ1：counting开头可空，测试""+y*n+"\b\n\b"
                if (debugPath) attackMsg += "----------------------------------------------------------\nnode regex: " + node.SelfRegex + "\nprePaths:\n" + printPaths(countingPrePaths.get(node), false) + "\npumpPaths:\n" + printPaths(node.paths, false) +"\n";
                if (haveEmptyBeginning(node)) {
                    if (debugPath) attackMsg += "SLQ1:\npump paths\n" + printPaths(node.paths, false) + "\n";
                    if (realTest) {
                        if (countingPrePaths.get(node).size() == 0) {
                            for (ArrayList<Set<Integer>> pumpPath : node.paths) {
                                if (Thread.currentThread().isInterrupted()) {
                                    System.out.println("线程请求中断...");
                                    return;
                                }
                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) return;
                            }
                        }
                        else {
                            for (ArrayList<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                if (Thread.currentThread().isInterrupted()) {
                                    System.out.println("线程请求中断...");
                                    return;
                                }
                                preEnum = new Enumerator(prePath);
                                for (ArrayList<Set<Integer>> pumpPath : node.paths) {
                                    if (Thread.currentThread().isInterrupted()) {
                                        System.out.println("线程请求中断...");
                                        return;
                                    }
                                    Enumerator pumpEnum = new Enumerator(pumpPath);
                                    if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) return;
                                }
                            }
                        }
                    }
                }
                else {
                    // SLQ2：counting开头不可空，判断前缀是否是中缀的子串，如果有重叠，测试""+(中缀&前缀）*n+"\b\n\b"
                    for (ArrayList<Set<Integer>> pumpPath : node.paths) {
                        for (ArrayList<Set<Integer>> prePath : countingPrePaths.get(node)) {
                            if(Thread.currentThread().isInterrupted()){
                                System.out.println("线程请求中断...");
                                if (debugPath) {
                                    try {
                                        attackMsg += "\nTraversing paths time out\n";
                                        attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                                    } catch (UnsupportedEncodingException e) {
                                        e.printStackTrace();
                                    }
                                    try {
                                        BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                                        writer.write(id + "," + attackMsg + "\n");
                                        writer.close();
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                                return;
                            }
                            if (prePath.size() == 0) continue;
                            // if (isPath2InPath1(pumpPath, prePath)) {
                            //     Enumerator pumpEnum = new Enumerator(pumpPath);
                            //     System.out.println("pre:");
                            //     System.out.println(printPath(prePath));
                            //     System.out.println("pump:");
                            //     System.out.println(printPath(pumpPath));
                            //     if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) return;
                            //     System.out.println("\n----------\n");
                            // }

                            ArrayList<ArrayList<Set<Integer>>> pumpPaths = new ArrayList<>();
                            if (isPath2InPath1_returnPaths(pumpPath, prePath, pumpPaths)) {
                                if (debugPath)  attackMsg += "SLQ2" + "\n" + "pre:" + "\n" + printPath(prePath, false) + "\n" + "pump:" + "\n" + printPath(pumpPath, false) + "\n"+ "pumpPaths:" + "\n" + printPaths(pumpPaths, false) + "\n";
                                if (realTest) {
                                    for (ArrayList<Set<Integer>> pumpPath_ : pumpPaths) {
                                        if (Thread.currentThread().isInterrupted()) {
                                            System.out.println("线程请求中断...");
                                            return;
                                        }
                                        Enumerator pumpEnum = new Enumerator(pumpPath_);
                                        // System.out.println("pre:");
                                        // System.out.println(printPath(prePath));
                                        // System.out.println("pump:");
                                        // System.out.println(printPath(pumpPath));
                                        if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) return;
                                    }
                                }
                            }
                        }
                    }
                }


            }
            System.out.println("[*] SLQ finished");
        }

        if (debugPath) {
            try {
                attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            try {
                BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                writer.write(id + "," + attackMsg + "\n");
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    Pair<ArrayList<ArrayList<Set<Integer>>>, LeafNode> getMidAndFrontNode(LeafNode node1, LeafNode node2) {
        Pair<ArrayList<ArrayList<Set<Integer>>>, ArrayList<ArrayList<Set<Integer>>>> result;
        ArrayList<ArrayList<Set<Integer>>> midPaths = new ArrayList<>();
        // 向上遍历，找到最小公共父节点
        LeafNode tmp = node1;
        LeafNode father = tmp;
        while (!id2childNodes.get(father.id).contains(node2.id)  && !Thread.currentThread().isInterrupted()) {
            father = tmp.father;
            tmp = father;
        }

        if (father instanceof ConnectNode) {
            ArrayList<ArrayList<Set<Integer>>> prefixPaths = new ArrayList<>();
            ArrayList<ArrayList<Set<Integer>>> suffixPaths = new ArrayList<>();
            LeafNode front = null, back = null;
            if (((ConnectNode) father).comeFromLeft(node1) && ((ConnectNode) father).comeFromRight(node2)) {
                // 说明node1在前，node2在后，node1求后缀，node2求前缀，在最小父节点相遇组合就是中间路径
                front = node1;
                back = node2;
            }
            else if (((ConnectNode) father).comeFromLeft(node2) && ((ConnectNode) father).comeFromRight(node1)) {
                // 说明node2在前，node1在后，node2求后缀，node1求前缀，在最小父节点相遇组合就是中间路径
                front = node2;
                back = node1;
            }

            tmp = front;
            LeafNode tmpfather = tmp.father;
            while (tmpfather != father && !Thread.currentThread().isInterrupted()) {
                if (tmpfather instanceof ConnectNode && ((ConnectNode) tmpfather).comeFromRight(tmp)) {
                    prefixPaths = splicePath(((ConnectNode) tmpfather).returnTrueLeftPaths(), prefixPaths);
                }
                tmp = tmpfather;
                tmpfather = tmp.father;
            }

            tmp = back;
            tmpfather = tmp.father;
            while (tmpfather != father && !Thread.currentThread().isInterrupted()) {
                if (tmpfather instanceof ConnectNode && ((ConnectNode) tmpfather).comeFromRight(tmp)) {
                    suffixPaths = splicePath(((ConnectNode) tmpfather).returnTrueLeftPaths(), suffixPaths);
                }
                tmp = tmpfather;
                tmpfather = tmp.father;
            }

            midPaths = splicePath(prefixPaths, suffixPaths);

            Collections.sort((midPaths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });

            return new Pair<>(midPaths, front);
        }
        else if (father instanceof BranchNode) {
            // 如果最小公共父节点是分支的话，说明之间不夹着东西，视作相邻，前缀都一样，随便返回一个即可
            return new Pair<>(midPaths, node1);
        }
        else {
            throw new Error("father is not ConnectNode or BranchNode");
        }
    }

    boolean isNode1ChildOfNode2(LeafNode node1, LeafNode node2) {
        if (id2childNodes.get(node2.id).contains(node1.id)) return true;
        return false;
    }

    boolean isPath2InPath1(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2) {
        // 默认path1是大串，path2是小串，如果path1.path.size() < path2.path.size()，return false
        if (path1.size() < path2.size()) {
            return false;
        } else {
            // ArrayList<oldPath> result = new ArrayList<>();
            // 对path1.path滑动窗口，从开始到path1.path.size() - path2.path.size()，每次滑动一位
            for (int i = 0; i < path1.size() - path2.size() + 1; i++) {
                // 对每一个滑动窗口，比较每一个节点的字符集
                ArrayList<Set<Integer>> charSet1 = new ArrayList<>();
                boolean path2InPath1 = true;
                for (int j = 0; j < path2.size(); j++) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.addAll(path1.get(i + j));
                    tmpCharSet.retainAll(path2.get(j));
                    if (tmpCharSet.size() == 0) {
                        path2InPath1 = false;
                        break;
                    } else {
                        charSet1.add(tmpCharSet);
                    }
                }
                if (path2InPath1) return true;
            }
        }
        return false;
    }

    boolean isPath2InPath1_returnPaths(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2, ArrayList<ArrayList<Set<Integer>>> result) {
        // 默认path1是大串，path2是小串，如果path1.path.size() < path2.path.size()，return false
        if (path1.size() < path2.size()) {
            return false;
        } else {
            // ArrayList<oldPath> result = new ArrayList<>();
            // 对path1.path滑动窗口，从开始到path1.path.size() - path2.path.size()，每次滑动一位
            for (int i = 0; i < path1.size() - path2.size() + 1 && !Thread.currentThread().isInterrupted(); i++) {
                // 对每一个滑动窗口，比较每一个节点的字符集
                ArrayList<Set<Integer>> charSet1 = new ArrayList<>();
                boolean path2InPath1 = true;
                for (int j = 0; j < path2.size() && !Thread.currentThread().isInterrupted(); j++) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.addAll(path1.get(i + j));
                    tmpCharSet.retainAll(path2.get(j));
                    if (tmpCharSet.size() == 0) {
                        path2InPath1 = false;
                        break;
                    } else {
                        charSet1.add(tmpCharSet);
                    }
                }

                // 如果path2在path1中，视作path1_1 + path1_2 + path1_3中的path1_2与path2有重叠
                // 把path1_1 + path1_2 & path2 + path1_3放入result
                if (path2InPath1) {
                    boolean rawPathHaveNoneSet = false;
                    // charSet1是path1_2 & path2，这一步为在其后添加path1_3
                    for (int j = i + path2.size(); j < path1.size() && !Thread.currentThread().isInterrupted(); j++) {
                        if (path1.get(j).size()==0) {
                            rawPathHaveNoneSet = true;
                            break;
                        }
                        charSet1.add(new HashSet<>(path1.get(j)));
                    }
                    // 构造tmpResult = path1_1
                    ArrayList<Set<Integer>> tmpResult = new ArrayList<Set<Integer>>();
                    for (int j = 0; j < i && !Thread.currentThread().isInterrupted(); j++) {
                        if (path1.get(j).size()==0) {
                            rawPathHaveNoneSet = true;
                            break;
                        }
                        tmpResult.add(new HashSet<>(path1.get(j)));
                    }
                    if (rawPathHaveNoneSet) continue;
                    // 使tmpResult = path1_1 + path1_2 & path2 + path1_3
                    else {
                        tmpResult.addAll(charSet1);
                        result.add(tmpResult);
                    }
                }
            }

            if (result.size() > 0) return true;
        }
        return false;
    }

    private boolean haveEmptyBeginning(LeafNode node) {
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                ArrayList<ArrayList<Set<Integer>>> prePaths = ((ConnectNode) father).returnTrueLeftPaths();
                if (prePaths.size() != 0 && prePaths.get(0).size() != 0 ) return false;
                if (((ConnectNode) father).beginInLeftPath()) return false;
            }
            node = father;
        }
        return true;
    }

    private boolean neverhaveEmptySuffix(LeafNode node) {
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromLeft(node)) {
                ArrayList<ArrayList<Set<Integer>>> suffixPaths = ((ConnectNode) father).returnTrueRightPaths();
                if (suffixPaths.size() != 0 && suffixPaths.get(0).size() != 0 ) return true;
                if (((ConnectNode) father).endInRight()) return true;
            }
            node = father;
        }
        return false;
    }

    enum VulType {
        OneCounting, POA, SLQ
    }

    /**
     * 对给定的前缀和中缀进行枚举并验证是否具有攻击性
     * @param preEnum 前缀枚举类
     * @param pumpEnum 中缀枚举类
     * @param type 检测的是OneCounting、POA、SLQ中哪类漏洞
     * @return 是否具有攻击性
     */
    private boolean dynamicValidate(Enumerator preEnum, Enumerator pumpEnum, VulType type) {
        int pumpMaxLength = 50;
        if (type == VulType.OneCounting) {
            pumpMaxLength = 50;
        } else if (type == VulType.POA) {
            pumpMaxLength = 10000;
        } else if (type == VulType.SLQ) {
            pumpMaxLength = 30000;
        }

        // 如果前缀可空的话，前缀固定为""，只枚举后缀
        if (preEnum.Empty()) {
            while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pump = pumpEnum.next();
                double matchingStepCnt;
                if (debugStep) System.out.println("pump: " + pump);
                if (type == VulType.SLQ) matchingStepCnt = testPattern4Search.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 100000);
                else matchingStepCnt = testPattern.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 100000);
                if (debugStep) System.out.println(matchingStepCnt);
                if (matchingStepCnt > 1e5) {
                    attackMsg = "";
                    try {
                        // type
                        attackMsg += type;
                        attackMsg += ",";
                        // pre
                        attackMsg += Base64.getEncoder().encodeToString("".getBytes("utf-8"));
                        attackMsg += ",";
                        // pump
                        attackMsg += Base64.getEncoder().encodeToString(pump.getBytes("utf-8"));
                        attackMsg += ",";
                        // suffix
                        attackMsg += Base64.getEncoder().encodeToString("\\n\\b\\n".getBytes("utf-8"));
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    System.out.println("MatchSteps: " + matchingStepCnt);
                    attackable = true;
                    // attackMsg = type + "\nprefix:\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                    return true;
                }
                // System.out.println("");
            }
        }
        // 如果前缀不可空的话，前缀和中缀组合枚举
        else {
            while (preEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pre = preEnum.next();
                while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                    String pump = pumpEnum.next();
                    double matchingStepCnt;
                    if (debugStep) System.out.println("pre:" + pre + "\npump:" + pump);
                    if (type == VulType.SLQ) matchingStepCnt = testPattern4Search.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 100000);
                    else matchingStepCnt = testPattern.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 100000);
                    if (debugStep) System.out.println(matchingStepCnt);
                    if (matchingStepCnt > 1e5) {
                        attackMsg = "";
                        try {
                            // type
                            attackMsg += type;
                            attackMsg += ",";
                            // pre
                            attackMsg += Base64.getEncoder().encodeToString(pre.getBytes("utf-8"));
                            attackMsg += ",";
                            // pump
                            attackMsg += Base64.getEncoder().encodeToString(pump.getBytes("utf-8"));
                            attackMsg += ",";
                            // suffix
                            attackMsg += Base64.getEncoder().encodeToString("\\n\\b\\n".getBytes("utf-8"));
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                        System.out.println("MatchSteps: " + matchingStepCnt);
                        attackable = true;
                        // attackMsg = type + "\nprefix:" + pre + "\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 当两条路径具有一条完全重合的路径时，返回重合路径
     * @param path1 路径1
     * @param path2 路径2
     * @return 路径1和2的重合路径
     */
    ArrayList<Set<Integer>> getPathCompletelyOverLap(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2) {
        ArrayList<Set<Integer>> result = new ArrayList<>();
        // 如果两条path的长度不同，则不可能有完全重叠
        if (path1.size() != path2.size()) {
            return result;
        }
        else {
            // 如果两个路径的长度相同，则需要比较每一个节点的字符集
            ArrayList<Set<Integer>> charSet1 = new ArrayList<>();
            for (int i = 0; i < path1.size() && !Thread.currentThread().isInterrupted(); i++) {
                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.addAll(path1.get(i));
                tmpCharSet.retainAll(path2.get(i));
                if (tmpCharSet.size() == 0) {
                    return result;
                } else {
                    charSet1.add(tmpCharSet);
                }
            }
            return charSet1;
        }
    }

    /**
     * 路径的枚举类，用来从一条路径中依次枚举出所有字符串
     */
    private class Enumerator {
        ArrayList<ArrayList<Integer>> path; // 把ArrayList<Set<Integer>>转换成ArrayList<ArrayList<Integer>>存储
        ArrayList<Integer> indexs; // 路径中的每一位所遍历到的序号

        public Enumerator(ArrayList<Set<Integer>> path) {
            this.indexs = new ArrayList<>();
            this.path = new ArrayList<>();
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.path.add(new ArrayList<>(path.get(i)));
                this.indexs.add(0);
            }
        }

        public String next() {
            String sb = "";
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                int tmp = path.get(i).get(indexs.get(i));
                sb += (char) tmp;
            }

            for (int i = indexs.size() - 1; i >= 0 && !Thread.currentThread().isInterrupted(); i--) {
                // 如果这一位的index遍历到头，则重置这一位，进入下一轮循环让下一位进位
                if (indexs.get(i) == path.get(i).size()) {
                    indexs.set(i, 0);
                    continue;
                } else {
                    // 如果这一位的index还没有遍历到头，让这一位的index加1
                    indexs.set(i, indexs.get(i) + 1);
                    // 如果这一位经过加1遍历到头的话，重置这一位，给前一位加1
                    for (int j = i; j > 0 && indexs.get(j) == path.get(j).size() && !Thread.currentThread().isInterrupted(); j--) {
                        indexs.set(j - 1, indexs.get(j - 1) + 1);
                        indexs.set(j, 0);
                    }
                    break;
                }
            }
            return sb;
        }

        public boolean hasNext() {
            if (this.indexs.size() == 0) {
                return false;
            }
            int t1 = this.indexs.get(0);
            int t2 = this.path.get(0).size();
            boolean result = t1 < t2;
            return result;
        }

        public boolean Empty() {
            return this.indexs.size() == 0;
        }

        public void reset() {
            for (int i = 0; i < this.indexs.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.indexs.set(i, 0);
            }
        }
    }

    // 普通的节点类，默认不可以向下连接其他节点，只能出现在叶子上
    private class LeafNode {
        Set<Integer> groupNums;
        LeafNode father;
        ArrayList<ArrayList<Set<Integer>>> paths;
        Pattern.Node actualNode;
        boolean beginInPath = false;
        boolean endInPath = false;
        int id;
        String SelfRegex = "";

        LeafNode (Set<Integer> groupNums, Pattern.Node actualNode) {
            this.groupNums = new HashSet<Integer>(groupNums);
            this.paths = new ArrayList<>();
            this.actualNode = actualNode;
        }

        LeafNode copy(LeafNode father) {
            LeafNode result = new LeafNode(new HashSet<>(), actualNode);
            result.paths = new ArrayList<>(this.paths);
            result.father = father;
            return result;
        }

        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +printPaths(paths, true)+"\"]");
        }

        void generateSelfRegex() {
            if (this.actualNode == null) return;

            if (this.actualNode instanceof Pattern.CharProperty) {
                Pattern.CharProperty cp = (Pattern.CharProperty) this.actualNode;
                if (cp.charSet.size() != 0) {
                    this.SelfRegex += "[";
                    if (setsEquals(cp.charSet, Dot)) this.SelfRegex += ".";
                    else if (setsEquals(cp.charSet, Bound)) this.SelfRegex += "\\b";
                    else if (setsEquals(cp.charSet, Space)) this.SelfRegex += "\\s";
                    else if (setsEquals(cp.charSet, noneSpace)) this.SelfRegex += "\\S";
                    else if (setsEquals(cp.charSet, All)) this.SelfRegex += "\\s\\S";
                    else if (setsEquals(cp.charSet, word)) this.SelfRegex += "\\w";
                    else if (setsEquals(cp.charSet, noneWord)) this.SelfRegex += "\\W";
                    else {
                        this.SelfRegex += cp.selfRegex;
                    }
                    this.SelfRegex += "]";
                }
            }
            else if (this.actualNode instanceof Pattern.SliceNode) {
                Pattern.SliceNode sn = (Pattern.SliceNode) this.actualNode;
                for (int i : sn.buffer) {
                    this.SelfRegex += int2String(i);
                }
            }
            else if (this.actualNode instanceof Pattern.BnM) {
                Pattern.BnM bn = (Pattern.BnM) this.actualNode;
                for (int i : bn.buffer) {
                    this.SelfRegex += int2String(i);
                }
            }
        }
    }

    private String int2String(int i) {
        return int2String(i, false);
    }

    private String int2String(int i, boolean mermaid) {

        switch (i) {
            case 7:
                return "\\a";
            case 8:
                return "\\b";
            case 9:
                return "\\t";
            case 10:
                return "\\n";
            case 11:
                return "\\v";
            case 12:
                return "\\f";
            case 13:
                return "\\r";
            case 92:
                return "\\\\";
            case 39:
                return "\\'";
            case 34:
                return mermaid ? "''" : "\\\"";
            case 72:
                return "\\(";
            case 123:
                return "\\{";
            case 91:
                return "\\[";
            case 46:
                return "\\.";
            case 124:
                return "\\|";
            case 42:
                return "\\*";
            case 63:
                return "\\?";
            case 43:
                return "\\+";
            default:
                return (char) i + "";
        }
    }

    // 能够连接其他节点的类拓展自LinkNode
    private abstract class LinkNode extends LeafNode {
        LinkNode(Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
        }

        abstract void replaceChild(LeafNode oldNode, LeafNode newNode);
    }

    // 连接结构
    private class ConnectNode extends LinkNode {
        LeafNode left;
        LeafNode right;
        ArrayList<ArrayList<Set<Integer>>> leftPaths;
        ArrayList<ArrayList<Set<Integer>>> rightPaths;

        ConnectNode (LeafNode left, LeafNode right, Set<Integer> groupNums) {
            super(groupNums, null);
            this.left = left;
            this.right = right;

            if (left != null) left.father = this;
            if (right != null) right.father = this;
        }

        /**
         * 根据左右子树路径生成本节点的路径
         */
        void generatePaths() {
            assignId2Node(this);
            leftPaths = new ArrayList<>();
            rightPaths = new ArrayList<>();

            if (left != null) {
                if (!(left instanceof LookaroundNode)) {
                    leftPaths.addAll(left.paths);
                    if (left.beginInPath) this.beginInPath = true;
                    if (left.endInPath) this.endInPath = true;
                }
                id2childNodes.get(this.id).add(left.id);
                id2childNodes.get(this.id).addAll(id2childNodes.get(left.id));
            }
            if (right != null) {
                if (!(right instanceof LookaroundNode)) {
                    rightPaths.addAll(right.paths);
                    if (right.beginInPath) this.beginInPath = true;
                    if (right.endInPath) this.endInPath = true;
                }
                id2childNodes.get(this.id).add(right.id);
                id2childNodes.get(this.id).addAll(id2childNodes.get(right.id));
            }

            if (leftPaths.size() == 0) {
                this.paths.addAll(rightPaths);
            }
            else if (rightPaths.size() == 0) {
                this.paths.addAll(leftPaths);
            }
            else {
                for (ArrayList<Set<Integer>> leftPath : leftPaths) {
                    for (ArrayList<Set<Integer>> rightPath : rightPaths) {
                        if(Thread.currentThread().isInterrupted()){
                            System.out.println("线程请求中断...");
                            return;
                        }
                        if (leftPath.size() + rightPath.size() > maxLength) {
                            continue;
                        }
                        ArrayList<Set<Integer>> newPath = new ArrayList<>();
                        newPath.addAll(leftPath);
                        newPath.addAll(rightPath);
                        this.paths.add(newPath);
                    }
                }
            }

            if(Thread.currentThread().isInterrupted()){
                System.out.println("线程请求中断...");
                return;
            }

            Collections.sort((this.paths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
        }

        @Override
        void generateSelfRegex(){
            if(left != null)
                this.SelfRegex += left.SelfRegex;
            if(right != null)
                this.SelfRegex += right.SelfRegex;
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            if (left == oldNode) {
                left = newNode;
                if (newNode != null) newNode.father = this;
            }
            else if (right == oldNode) {
                right = newNode;
                if (newNode != null) newNode.father = this;
            }
        }

        boolean comeFromLeft(LeafNode node) {
            return node == left || (right!=null && id2childNodes.get(left.id).contains(node.id));
        }

        boolean comeFromRight(LeafNode node) {
            return node == right || (right!=null && id2childNodes.get(right.id).contains(node.id));
        }

        ArrayList<ArrayList<Set<Integer>>> returnTrueLeftPaths() {
            ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
            if (left != null && !(left instanceof LookaroundNode)) result.addAll(left.paths);
            return result;
        }

        ArrayList<ArrayList<Set<Integer>>> returnTrueRightPaths() {
            ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
            if (right != null && !(right instanceof LookaroundNode)) result.addAll(right.paths);
            return result;
        }

        boolean beginInLeftPath() {
            if (left != null && !(left instanceof LookaroundNode)) return left.beginInPath;
            return false;
        }

        boolean endInRight() {
            if (right != null && !(right instanceof LookaroundNode)) return right.endInPath;
            return false;
        }

        @Override
        ConnectNode copy(LeafNode father) {
            ConnectNode result =  new ConnectNode(null, null, new HashSet<>());
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 分支结构
    private class BranchNode extends LinkNode {
        ArrayList<LeafNode> children;
        Map<LeafNode, ArrayList<ArrayList<Set<Integer>>>> childrenPaths;

        BranchNode (Pattern.Node actualNode, Set<Integer> groupNums) {
            super(groupNums, actualNode);
            children = new ArrayList<>();
            childrenPaths = new HashMap<>();
        }

        void addChild (LeafNode child) {
            if (child != null) {
                children.add(child);
                child.father = this;
            }
        }

        void generatePaths() {
            assignId2Node(this);
            this.beginInPath = true;
            this.endInPath = true;
            for (LeafNode child : children) {
                if(Thread.currentThread().isInterrupted()){
                    System.out.println("线程请求中断...");
                    return;
                }
                childrenPaths.put(child, new ArrayList<>(child.paths));
                if (!(child instanceof LookaroundNode)) {
                    this.paths.addAll(child.paths);
                    if (!child.beginInPath) this.beginInPath = false;
                    if (!child.endInPath) this.endInPath = false;
                }
                id2childNodes.get(this.id).add(child.id);
                id2childNodes.get(this.id).addAll(id2childNodes.get(child.id));
            }
            Collections.sort((this.paths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "(";
            int count = 0;
            for (LeafNode child : children) {
                if(Thread.currentThread().isInterrupted()){
                    System.out.println("线程请求中断...");
                    return;
                }
                if (child != null) {
                    if (count != 0) this.SelfRegex += "|";
                    this.SelfRegex += child.SelfRegex;
                    count++;
                }
            }
            this.SelfRegex += ")";
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            for (int i = 0; i < children.size(); i++) {
                if(Thread.currentThread().isInterrupted()){
                    System.out.println("线程请求中断...");
                    return;
                }
                if (children.get(i) == oldNode) {
                    children.set(i, newNode);
                    if (newNode != null) newNode.father = this;
                    childrenPaths.put(newNode, childrenPaths.get(oldNode));
                    childrenPaths.remove(oldNode);
                    break;
                }
            }
        }

        @Override
        BranchNode copy(LeafNode father) {
            BranchNode result =  new BranchNode(this.actualNode, new HashSet<>());
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 循环结构
    private class LoopNode extends LinkNode {
        int cmin;
        int cmax;
        LeafNode atom;
        ArrayList<ArrayList<Set<Integer>>> atomPaths;

        LoopNode (int cmin, int cmax, LeafNode atom, Pattern.Node actualNode, Set<Integer> groupNums) {
            super(groupNums, actualNode);
            this.cmin = cmin;
            this.cmax = cmax;
            this.atom = atom;
            if (atom != null) atom.father = this;
        }

        void generatePaths() {
            assignId2Node(this);
            this.atomPaths = new ArrayList<>();
            if (atom != null) {
                if (!(atom instanceof LookaroundNode)) {
                    this.atomPaths.addAll(atom.paths);
                    if (cmin != 0) this.beginInPath = atom.beginInPath;
                    if (cmin != 0) this.endInPath = atom.endInPath;
                }
                id2childNodes.get(this.id).add(atom.id);
                id2childNodes.get(this.id).addAll(id2childNodes.get(atom.id));
            }

            ArrayList<ArrayList<Set<Integer>>> lastPaths = new ArrayList<>();
            lastPaths.add(new ArrayList<>());

            for (int i = 0; i < cmin && !Thread.currentThread().isInterrupted(); i++) {
                ArrayList<ArrayList<Set<Integer>>> newPaths = new ArrayList<>();
                for (ArrayList<Set<Integer>> atomPath : atomPaths) {
                    if (atomPath.size() == 0) continue;
                    for (ArrayList<Set<Integer>> lastPath : lastPaths) {
                        if(Thread.currentThread().isInterrupted()){
                            System.out.println("线程请求中断...");
                            return;
                        }
                        if (lastPath.size() + atomPath.size() > maxLength) {
                            continue;
                        }
                        ArrayList<Set<Integer>> newPath = new ArrayList<>();
                        newPath.addAll(lastPath);
                        newPath.addAll(atomPath);
                        newPaths.add(newPath);
                    }
                }
                lastPaths = newPaths;
            }

            this.paths = new ArrayList<>();
            for (int i = cmin; i < cmax && i < maxLength && !Thread.currentThread().isInterrupted(); i++) {
                this.paths.addAll(lastPaths);
                ArrayList<ArrayList<Set<Integer>>> newPaths = new ArrayList<>();
                for (ArrayList<Set<Integer>> atomPath : atomPaths) {
                    if (atomPath.size() == 0) continue;
                    for (ArrayList<Set<Integer>> lastPath : lastPaths) {
                        if(Thread.currentThread().isInterrupted()){
                            System.out.println("线程请求中断...");
                            return;
                        }
                        if (lastPath.size() + atomPath.size() > maxLength) {
                            continue;
                        }
                        ArrayList<Set<Integer>> newPath = new ArrayList<>();
                        newPath.addAll(lastPath);
                        newPath.addAll(atomPath);
                        newPaths.add(newPath);
                    }
                }
                lastPaths = newPaths;
            }
            this.paths.addAll(lastPaths);

            Collections.sort((this.paths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
        }

        @Override
        void generateSelfRegex(){
            if (atom != null) {
                this.SelfRegex += "(" + atom.SelfRegex + ")" + "{" + cmin + "," + (cmax > 100 ? "100" : cmax) + "}";
            }
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            this.atom = newNode;
            if (newNode != null) newNode.father = this;
            this.atomPaths = new ArrayList<>(newNode.paths);
        }

        @Override
        LoopNode copy(LeafNode father) {
            LoopNode result =  new LoopNode(cmin, cmax, null, this.actualNode, new HashSet<>());
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + "cmin = " + cmin + "\\ncmax = " + cmax + "\\n"
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    enum lookaroundType {
        Pos, Neg, Behind, NotBehind
    }

    // lookaround用一个一元结构独立出来
    private class LookaroundNode extends LinkNode {
        LeafNode atom;
        lookaroundType type;

        LookaroundNode(LeafNode atom, lookaroundType type, Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.atom = atom;
            this.type = type;
            if (atom != null) atom.father = this;
        }

        void generatePaths() {
            assignId2Node(this);
            this.paths.addAll(atom.paths);
            this.beginInPath = atom.beginInPath;
            this.endInPath = atom.endInPath;
            id2childNodes.get(this.id).add(atom.id);
            id2childNodes.get(this.id).addAll(id2childNodes.get(atom.id));
        }

        @Override
        void generateSelfRegex(){
            if (atom != null) {
                switch (type) {
                    case Pos:
                        this.SelfRegex += "(?=" + atom.SelfRegex + ")";
                        break;
                    case Neg:
                        this.SelfRegex += "(?!" + atom.SelfRegex + ")";
                        break;
                    case Behind:
                        this.SelfRegex += "(?<=" + atom.SelfRegex + ")";
                        break;
                    case NotBehind:
                        this.SelfRegex += "(?<!" + atom.SelfRegex + ")";
                        break;
                }
            }
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            this.atom = newNode;
            if (newNode != null) newNode.father = this;
            this.paths = new ArrayList<>(newNode.paths);
        }

        @Override
        LookaroundNode copy(LeafNode father) {
            LookaroundNode result =  new LookaroundNode(null, type, new HashSet<>(), this.actualNode);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + "type = " + type.toString() + "\\n"
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 反向引用
    private class BackRefNode extends LeafNode {
        int groupIndex;
        BackRefNode (int groupIndex, Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.groupIndex = groupIndex;
        }

        @Override
        BackRefNode copy(LeafNode father) {
            BackRefNode result = new BackRefNode(groupIndex, new HashSet<>(), this.actualNode);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + "groupIndex = " + groupIndex + "\\n"
                    + "localIndex = " + groupIndex2LocalIndex.get(groupIndex) + "\\n"
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 整个正则的终止符节点
    private class LastNode extends LeafNode {
        LastNode (Pattern.Node lastNode, Set<Integer> groupNums) {
            super(groupNums, lastNode);
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_"));
        }
    }

    // "^"符号
    private class Begin extends LeafNode {
        Begin (Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.beginInPath = true;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "^";
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "^" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +"\"]");
        }
    }

    // "$"符号
    private class End extends LeafNode {
        End (Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.endInPath = true;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "$";
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "$" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +"\"]");
        }
    }

    // "\b"符号或者"\B"符号，\b为type3，\B为type4
    private class WordBoundary extends LeafNode {
        int type;
        WordBoundary (Set<Integer> groupNums, int type, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.endInPath = true;
            this.type = type;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = type == 3 ? "\\b" : "\\B";
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ (this.type == 3 ? "\\b" : "\\B") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex + "\\n" : "")
                    +"\"]");
        }
    }

    /**
     * 为一个节点生成对应的前缀路径
     * @param countingNode 需要生成前缀路径的节点
     * @return 该节点的前缀路径
     */
    private ArrayList<ArrayList<Set<Integer>>> generatePrePath(LeafNode countingNode) {
        LeafNode node = countingNode;
        ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                // ArrayList<ArrayList<Set<Integer>>> left = ((ConnectNode) father).returnTrueLeftPaths();
                ArrayList<ArrayList<Set<Integer>>> tmp = splicePath(((ConnectNode) father).returnTrueLeftPaths(), result);
                if (result.size() != 0 && tmp.size() == 0) {
                    return new ArrayList<>();
                }
                result = tmp;
            }
            // else if (father instanceof LoopNode && ((LoopNode) father).cmin == 0) {
            //     result.add(new ArrayList<>());
            // }
            node = father;
        }
        if (result.size() == 0) result.add(new ArrayList<>());
        return result;
    }

    private String generatePreRegex(LeafNode countingNode) {
        LeafNode node = countingNode;
        String result = "";
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                result = (((ConnectNode) father).left == null) ? "" : ((ConnectNode) father).left.SelfRegex + result;
            }
            node = father;
        }
        return result;
    }

    /**
     * 将传入的两个路径排列组合地拼接在一起，同时满足生成结果小于全局的maxlength限制
     * @param prefix 被生成路径的前缀
     * @param suffix 被生成路径的后缀
     * @return 前缀+后缀
     */
    private ArrayList<ArrayList<Set<Integer>>> splicePath(ArrayList<ArrayList<Set<Integer>>> prefix, ArrayList<ArrayList<Set<Integer>>> suffix) {
        ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
        if (prefix.size() == 0) {
            result.addAll(suffix);
        }
        else if (suffix.size() == 0) {
            result.addAll(prefix);
        }
        else {
            for (ArrayList<Set<Integer>> prefixPath : prefix) {
                for (ArrayList<Set<Integer>> suffixPath : suffix) {
                    if(Thread.currentThread().isInterrupted()){
                        System.out.println("线程请求中断...");
                        return result;
                    }
                    if (prefixPath.size() + suffixPath.size() <= maxLength) {
                        ArrayList<Set<Integer>> newPath = new ArrayList<>();
                        newPath.addAll(prefixPath);
                        newPath.addAll(suffixPath);
                        result.add(newPath);
                    }
                }
            }
        }
        return result;
    }

    /**
     * 对传入的树，递归地生成每一个节点的Path，同时记录每个循环节点，并为每个节点分配id且记录每个节点下属所有孩子节点的id
     * @param root 根节点
     */
    private void generateAllPath(LeafNode root, boolean inLookaround) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return;
        }
        if (root == null) {
            return;
        }
        else if (root instanceof LinkNode) {
            if (root instanceof ConnectNode) {
                generateAllPath(((ConnectNode) root).left, inLookaround);
                generateAllPath(((ConnectNode) root).right, inLookaround);
                ((ConnectNode) root).generatePaths();
            }
            else if (root instanceof BranchNode) {
                for (LeafNode node : ((BranchNode) root).children) {
                    generateAllPath(node, inLookaround);
                }
                ((BranchNode) root).generatePaths();
            }
            else if (root instanceof LoopNode) {
                generateAllPath(((LoopNode) root).atom, inLookaround);
                ((LoopNode) root).generatePaths();
                if(!inLookaround) countingNodes.add(root);
            }
            else if (root instanceof LookaroundNode) {
                generateAllPath(((LookaroundNode) root).atom, true);
                ((LookaroundNode) root).generatePaths();
            }
        }
        else if (root instanceof LeafNode) {
            assignId2Node(root);
            if (root.actualNode == null) {
                return;
            }
            else if (root.actualNode instanceof Pattern.CharProperty) {
                root.paths = new ArrayList<>();
                ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
                if (((Pattern.CharProperty) root.actualNode).charSet.size() > 0) {
                    tmpPath.add(((Pattern.CharProperty) root.actualNode).charSet);
                }
                root.paths.add(tmpPath);
            }
        }
        root.generateSelfRegex();
    }

    private void assignId2Node(LeafNode node) {
        node.id = id++;
        id2childNodes.put(node.id, new HashSet<>());
    }

    /**
     * 根据优化要求，对整个正则树进行修改，返回实际用来生成路径的新树
     * @param root 原始的正则表达书
     * @return 经过优化后的用来生成路径的树
     */
    private LeafNode buildFinalTree(LeafNode root) {
        // 1. 反向引用替换（不支持嵌套）
        for (LeafNode node : backRefNodes) {
            int localIndex = groupIndex2LocalIndex.get(((BackRefNode)node).groupIndex);
            LeafNode rawGroupRoot = groupStartNodesMap.get(localIndex);
            ((LinkNode)node.father).replaceChild(node, copyGroupTree(rawGroupRoot, groupIndex2LocalIndex.get(((BackRefNode)node).groupIndex), node.father));
        }

        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return null;
        }

        // 2. 判断是否在前部加入.{0,3}
        if (branchAtFirst(root) == 1) {
            // 在前部加入.{0,3}
            Pattern dotPattern = Pattern.compile(".{0,3}");
            LeafNode dotTree = buildTree(dotPattern.root, new HashSet<>());

            root = new ConnectNode(dotTree, root, new HashSet<>());
        }

        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return null;
        }

        // 3. 是将结尾的lookaround拿出还是在尾部添加[\s\S]*
        // a. 如果结尾单独一个lookaround，则需要把lookaround拿出来缀在末尾
        searchLookaroundAtLast(root);
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return root;
        }
        if (lookaroundAtLast.size() == 1) {
            ((LinkNode)lookaroundAtLast.get(0).father).replaceChild(lookaroundAtLast.get(0), ((LookaroundNode)lookaroundAtLast.get(0)).atom);
        }
        // b. 如果结尾有多个连续的lookaround，则需要在结尾加上[\s\S]*
        if (lookaroundAtLast.size() > 1) {
            for (LeafNode node : lookaroundAtLast) {
                if(Thread.currentThread().isInterrupted()){
                    System.out.println("线程请求中断...");
                    return root;
                }
                ((LinkNode)node.father).replaceChild(node, null);
            }
            Pattern tailPattern = Pattern.compile("[\\s\\S]*");
            LeafNode tailTree = buildTree(tailPattern.root, new HashSet<>());
            root = new ConnectNode(root, tailTree, new HashSet<>());
        }

        // 4. 在树外围包裹ConnectNode--right-->LastNode
        root = new ConnectNode(root, new LastNode(lastNode, new HashSet<>()), new HashSet<>());
        return root;
    }

    /**
     * 根据传入的组号，拷贝所有带有此组号的节点，组成新树
     * @param root 带有特定组号的树的根节点
     * @param localIndex 组号
     * @param father 新节点的父节点
     * @return 拷贝出来的新节点
     */
    private LeafNode copyGroupTree(LeafNode root, int localIndex, LeafNode father) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return null;
        }
        LeafNode result = null;
        if (root == null){
            return null;
        }
        else if (root.groupNums.contains(localIndex)) {
            result = root.copy(father);
            if (root instanceof Analyzer.ConnectNode) {
                ((Analyzer.ConnectNode)result).left = copyGroupTree(((ConnectNode)root).left, localIndex, result);
                ((Analyzer.ConnectNode)result).left = copyGroupTree(((ConnectNode)root).left, localIndex, result);
            }
            else if (root instanceof Analyzer.BranchNode) {
                for (LeafNode child : ((BranchNode)root).children) {
                    ((BranchNode)result).children.add(copyGroupTree(child, localIndex, result));
                }
            }
            else if (root instanceof Analyzer.LoopNode) {
                ((LoopNode)result).atom = copyGroupTree(((LoopNode)root).atom, localIndex, result);
            }
            else if (root instanceof Analyzer.LookaroundNode) {
                ((LookaroundNode)result).atom = copyGroupTree(((LookaroundNode)root).atom, localIndex, result);
            }
        }
        else {
            return null;
        }
        return result;
    }

    /**
     * 递归建立原始的正则表达式树
     * @param root Pattern.Node节点
     * @param rawgroupNums 从递归上层传下来的组号
     * @return 本层递归节点需要返回的LeafNode
     */
    private LeafNode buildTree(Pattern.Node root, Set<Integer> rawgroupNums) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return null;
        }
        LeafNode result = null;
        LeafNode me = null;
        LeafNode brother = null;
        Set<Integer> groupNums = new HashSet<>(rawgroupNums);
        if (root == null || (root instanceof Pattern.GroupTail && root.next instanceof Pattern.Loop)) {
            return null;
        }
        else if (root instanceof Pattern.LastNode) {
            lastNode = root;
            return null;
        }

        else if (root instanceof Pattern.GroupHead) {
            groupNums.add(((Pattern.GroupHead) root).localIndex);
            result = buildTree(root.next, groupNums);
            groupStartNodesMap.put(((Pattern.GroupHead) root).localIndex, result);
            return result;
        }
        else if (root instanceof Pattern.GroupTail) {
            groupNums.remove(((Pattern.GroupTail) root).localIndex);
            groupIndex2LocalIndex.put(((Pattern.GroupTail) root).groupIndex, ((Pattern.GroupTail) root).localIndex);
            return buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.BackRef || root instanceof Pattern.CIBackRef || root instanceof Pattern.GroupRef) {
            me = new BackRefNode(((Pattern.BackRef)root).groupIndex, groupNums, root);
            backRefNodes.add(me);
            brother = buildTree(root.next, groupNums);
        }

        // 需要特殊处理的节点（下一个节点不在next或者不止在next）
        else if (root instanceof Pattern.Prolog) {
            return buildTree(((Pattern.Prolog)root).loop, groupNums);
        }
        else if (root instanceof Pattern.Loop) {
            me = new LoopNode(((Pattern.Loop)root).cmin, ((Pattern.Loop)root).cmax, buildTree(((Pattern.Loop)root).body, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Curly) {
            me = new LoopNode(((Pattern.Curly)root).cmin, ((Pattern.Curly)root).cmax, buildTree(((Pattern.Curly)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.GroupCurly) {
            groupNums.add(((Pattern.GroupCurly) root).groupIndex);
            me = new LoopNode(((Pattern.GroupCurly)root).cmin, ((Pattern.GroupCurly)root).cmax, buildTree(((Pattern.GroupCurly)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }

        // 2. 分支
        else if(root instanceof Pattern.Branch){
            if (((Pattern.Branch) root).getSize() == 1) {
                me = new LoopNode(0,1, buildTree(((Pattern.Branch)root).atoms[0], groupNums), root, groupNums);
            }
            else {
                me = new BranchNode(root, groupNums);
                for (Pattern.Node node : ((Pattern.Branch) root).atoms) {
                    if (node == null) {
                        continue;
                    }
                    ((BranchNode) me).addChild(buildTree(node, groupNums));
                }
            }
            brother = buildTree(((Pattern.Branch) root).conn.next, groupNums);
        }
        else if (root instanceof Pattern.BranchConn) {
            return null;
        }
        else if(root instanceof Pattern.Ques){
            me = new LoopNode(0,1, buildTree(((Pattern.Ques)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }

        // 具有实际字符意义
        else if (root instanceof Pattern.CharProperty){
            generateFullSmallCharSet((Pattern.CharProperty) root);

            me = new LeafNode(groupNums, root);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            tmpPath.add(((Pattern.CharProperty) root).charSet);
            me.paths.add(tmpPath);

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.SliceNode){
            me = new LeafNode(groupNums, root);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            for (int i : ((Pattern.SliceNode) root).buffer) {
                fullSmallCharSet.add(i);

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                tmpPath.add(tmpCharSet);
            }
            me.paths.add(tmpPath);

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.BnM) {
            me = new LeafNode(groupNums, root);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            for (int i : ((Pattern.BnM) root).buffer) {
                fullSmallCharSet.add(i);

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                tmpPath.add(tmpCharSet);
            }
            me.paths.add(tmpPath);

            brother = buildTree(root.next, groupNums);
        }

        // lookaround处理
        else if (root instanceof Pattern.Pos){
            me = new LookaroundNode(buildTree(((Pattern.Pos)root).cond, groupNums), lookaroundType.Pos, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Neg){
            me = new LookaroundNode(buildTree(((Pattern.Neg)root).cond, groupNums), lookaroundType.Neg, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Behind){
            me = new LookaroundNode(buildTree(((Pattern.Behind)root).cond, groupNums), lookaroundType.Behind, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.NotBehind){
            me = new LookaroundNode(buildTree(((Pattern.NotBehind)root).cond, groupNums), lookaroundType.NotBehind, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }

        // "^"、"$"
        else if (root instanceof Pattern.Begin || root instanceof Pattern.Caret || root instanceof Pattern.UnixCaret) {
            me = new Begin(groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Dollar || root instanceof Pattern.UnixDollar) {
            me = new End(groupNums, root);
            brother = buildTree(root.next, groupNums);
        }

        // "\b"、"\B"
        else if (root instanceof Pattern.Bound) {
            me = new WordBoundary(groupNums, ((Pattern.Bound) root).type, root);
            brother = buildTree(root.next, groupNums);
        }

        else {
            return buildTree(root.next, groupNums);
        }


        if (brother != null) {
            result = new ConnectNode(me, brother, groupNums);
            return result;
        } else {
            return me;
        }
    }

    /**
     * 生成所有“实际字符”节点的原始内容，记录“小字符全集”和“大字符集”节点
     * @param root
     */
    private void generateFullSmallCharSet(Pattern.CharProperty root) {
        Set<Integer> charSet = new HashSet<>();
        root.selfRegex = "";
        int count = 0;
        for (int i = 0; i < 256 && !Thread.currentThread().isInterrupted(); i++) {
            if (root.isSatisfiedBy(i)) {
                charSet.add(i);

                count++;
                if (count == 1) {
                    String hex = Integer.toHexString(i);
                    while (hex.length() < 2) {
                        hex = "0" + hex;
                    }
                    root.selfRegex += "\\x"+hex;
                }
            }
            else {
                if (count > 1) {
                    // root.selfRegex += "-" + ((i==34||i==91||i==92) ? "\\" : "") + (char) (i - 1);
                    String hex = Integer.toHexString(i - 1);
                    while (hex.length() < 2) {
                        hex = "0" + hex;
                    }
                    root.selfRegex += "-" + "\\x"+hex;
                }
                count = 0;
            }
        }
        if (count > 1) {
            String hex = Integer.toHexString(255);
            root.selfRegex += "-" + "\\x"+hex;
        }
        root.charSet.addAll(charSet);
        if (charSet.size() < 128) {
            fullSmallCharSet.addAll(charSet);
        } else {
            bigCharSetMap.put(root, charSet);
        }
    }

    /**
     * 遍历bigCharSetMap，调用generateBigCharSet
     */
    private void generateAllBigCharSet() {
        // 遍历化bigCharSetMap节点
        for (Map.Entry<Pattern.Node, Set<Integer>> entry : bigCharSetMap.entrySet()) {
            if(Thread.currentThread().isInterrupted()){
                System.out.println("线程请求中断...");
                return;
            }
            Pattern.CharProperty root = (Pattern.CharProperty) entry.getKey();
            generateBigCharSet(root);
        }

    }

    /**
     * 压缩所有“大字符集”节点的charSet
     * @param root
     */
    private void generateBigCharSet(Pattern.CharProperty root) {

        if (bigCharSetMap.size() > 20) {
            Set<Integer> charSet = new HashSet<>();
            for (int i = 0; i < 128 && !Thread.currentThread().isInterrupted(); i++) {
                if (root.isSatisfiedBy(i)) {
                    charSet.add(i);
                }
            }
            root.charSet.addAll(charSet);
            return;
        }

        Random rand = new Random();
        Set<Integer> result = new HashSet<>();

        // set2&set8
        Set<Integer> tmp;

        for (Map.Entry<Pattern.Node, Set<Integer>> entry : bigCharSetMap.entrySet()) {
            if(Thread.currentThread().isInterrupted()){
                System.out.println("线程请求中断...");
                return;
            }
            if (entry.getKey() == root) {
                // 加入root和fullSmallCharSet的交集
                // set2&set8
                tmp = new HashSet<>(entry.getValue());
                tmp.retainAll(fullSmallCharSet);
                result.addAll(tmp);
                continue;
            } else {
                // 加入和本bigCharSet的差集
                // (set2-set5)
                tmp = new HashSet<>(bigCharSetMap.get(root));
                tmp.removeAll(entry.getValue());
                result.addAll(tmp);

                // 随机加入一个root和本bigCharSet的并集-其他bigCharSet
                // random 1个(set2&set5-set7-set8)
                tmp = new HashSet<>(bigCharSetMap.get(root));
                tmp.retainAll(entry.getValue());
                tmp.removeAll(fullSmallCharSet);
                for (Map.Entry<Pattern.Node, Set<Integer>> entry_ : bigCharSetMap.entrySet()) {
                    if(Thread.currentThread().isInterrupted()){
                        System.out.println("线程请求中断...");
                        return;
                    }
                    if (entry_.getKey() == root || entry_.getKey() == entry.getKey()) {
                        continue;
                    } else {
                        tmp.removeAll(entry_.getValue());
                    }
                }

                if (tmp.size() > 0) {
                    int index = rand.nextInt(tmp.size());
                    Iterator<Integer> iter = tmp.iterator();
                    for (int i = 0; i < index && !Thread.currentThread().isInterrupted(); i++) {
                        iter.next();
                    }
                    result.add(iter.next());
                }
            }
        }

        // 最后random 1个(set2-set8)
        tmp = new HashSet<>(bigCharSetMap.get(root));
        tmp.removeAll(fullSmallCharSet);
        if (tmp.size() > 0) {
            int index = rand.nextInt(tmp.size());
            Iterator<Integer> iter = tmp.iterator();
            for (int i = 0; i < index && !Thread.currentThread().isInterrupted(); i++) {
                iter.next();
            }
            result.add(iter.next());
        }

        root.charSet = new HashSet<>();
        root.charSet.addAll(result);
    }

    /**
     * 后序遍历，捕获所有后缀为空的lookaround，直到遇到实际字符
     * @param root
     * @return 遇到实际字符返回false，可空返回true
     */
    private boolean searchLookaroundAtLast(LeafNode root) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return false;
        }
        if (root == null || root.actualNode instanceof Pattern.CharProperty || root.actualNode instanceof Pattern.SliceNode || root.actualNode instanceof Pattern.BnM) {
            return false;
        }
        else if (root instanceof LookaroundNode && ((LookaroundNode) root).type == lookaroundType.Pos) {
            // 如果顺利遇到lookaround，放入lookaroundAtLast，假装可空继续向前找
            lookaroundAtLast.add(root);
            return true;
        }
        else if (root instanceof ConnectNode) {
            // 先看右边，右边如果遇到实际字符直接返回
            if (!searchLookaroundAtLast(((ConnectNode) root).right)) return false;

            // 右边如果可空则看左边，左边可空则整个节点可空，如实返回；左边遇到实际字符则说明不能继续，也直接返回
            return searchLookaroundAtLast(((ConnectNode) root).left);
        }
        else if (root instanceof BranchNode) {
            boolean tmp = false;
            for (LeafNode child : ((BranchNode) root).children) {
                if (searchLookaroundAtLast(child)) {
                    // 孩子中有一个可空，则视为整个Node可空
                    tmp = true;
                }
            }
            return tmp;
        }
        else if (root instanceof LoopNode) {
            // 看孩子是否可空
            boolean tmp = searchLookaroundAtLast(((LoopNode) root).atom);

            // 如果孩子遇到了实际字符，但是循环次数可以为0，那么返回可空
            if (!tmp && ((LoopNode) root).cmin == 0) return true;

            // 孩子可空、孩子不可空且循环次数不能为0等情况都如实返回
            else return tmp;
        }
        else {
            // 对于LastNode、Begin、End都返回可空，BackRefNode之前应该都处理过了（没处理说明是嵌套，也没办法了，不做处理）
            return true;
        }
    }

    /**
     * 判断是否有branch节点在开头
     * @param root
     * @return "实际字符"开头返回0，遇到可空字符返回2，遇到分支返回1
     */
    private int branchAtFirst (LeafNode root) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...");
            return 0;
        }
        if (root.actualNode instanceof Pattern.CharProperty || root.actualNode instanceof Pattern.SliceNode || root.actualNode instanceof Pattern.BnM) {
            return 0;
        }
        else if (root instanceof BranchNode) {
            return 1;
        }
        else if (root instanceof ConnectNode) {
            // 先看左边，左边如果遇到实际字符或者以branch开头都如实返回
            int tmp = branchAtFirst(((ConnectNode) root).left);
            if (tmp == 0) return 0;
            else if (tmp == 1) return 1;

            // 左边如果可空则看右边，右边遇到实际字符或者以branch开头也如实返回
            tmp = branchAtFirst(((ConnectNode) root).right);
            if (tmp == 0) return 0;
            else if (tmp == 1) return 1;

            // 左右如果都可空，返回可空
            else return 2;
        }
        else if (root instanceof LoopNode) {
            // 看孩子是否能以branch开头
            int tmp = branchAtFirst(((LoopNode) root).atom);

            // 如果孩子遇到了实际字符，但是循环次数可以为0，那么返回可空
            if (tmp == 0 && ((LoopNode) root).cmin == 0) return 2;

            // branch开头，孩子也可空，孩子不可空且循环次数不能为0等情况都如实返回
            else return tmp;
        }
        else {
            // 对于Lookaround、LastNode、Begin、End都返回可空，BackRefNode之前应该都处理过了（没处理说明是嵌套，也没办法了，不做处理）
            return 2;
        }
    }

    /**
     * 将以传入节点为根的树，以Markdown中Mermaid语法打印在输出中
     * @param root 树的根节点
     * @param debug 是否打印详细信息（每个节点的路径、组号）
     */
    private void printTree(LeafNode root, boolean debug) {
        if (root == null) return;
        else if (root instanceof Analyzer.ConnectNode) {
            ((ConnectNode) root).print(debug);
            if (((ConnectNode)root).left != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_")+"--left-->"+((ConnectNode)root).left.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((ConnectNode)root).left, debug);
            }
            if (((ConnectNode)root).right != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_")+"--right-->"+((ConnectNode)root).right.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((ConnectNode)root).right, debug);
            }
        }
        else if (root instanceof Analyzer.BranchNode) {
            ((BranchNode) root).print(debug);
            for (LeafNode child : ((BranchNode)root).children) {
                if (child != null) {
                    System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--child-->" + child.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                    printTree(child, debug);
                }
            }
        }
        else if (root instanceof Analyzer.LoopNode) {
            ((LoopNode) root).print(debug);
            if (((LoopNode)root).atom != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--atom-->" + ((LoopNode) root).atom.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((LoopNode) root).atom, debug);
            }
        }
        else if (root instanceof Analyzer.LookaroundNode) {
            ((LookaroundNode) root).print(debug);
            if (((LookaroundNode)root).atom != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--atom-->" + ((LookaroundNode) root).atom.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((LookaroundNode) root).atom, debug);
            }
        }
        else {
            root.print(debug);
        }
    }

    /**
     * 生成一组路径的字符串
     * @param paths ArrayList<Set<Integer>>格式路径的列表
     * @return 形如“[a,b,c],[d]\\n[a,b,c],[e]”的字符串，每条路径之间用"\\n"分割
     */
    private String printPaths (ArrayList<ArrayList<Set<Integer>>> paths, boolean mermaid) {
        String result = "";

        if (paths.size() > 30) {
            result = "paths.size():"+paths.size()+(mermaid ? "\\n" : "\n");
            for (int i = 0; i < 10; i++) {
                result += printPath(paths.get(i), mermaid);
                result += (mermaid ? "\\n" : "\n");
            }
            result += "...";
        }
        else {
            for (ArrayList<Set<Integer>> path : paths) {
                result += printPath(path, mermaid);
                result += mermaid ? "\\n" : "\n";
            }
        }
        return result;
    }

    //获取特定类别的节点set
    Set<Integer> Dot = getNodeCharSet(DotP.root.next);
    Set<Integer> Bound = getNodeCharSet(BoundP.root.next);
    Set<Integer> Space = getNodeCharSet(SpaceP.root.next);
    Set<Integer> noneSpace = getNodeCharSet(noneSpaceP.root.next);
    Set<Integer> word = getNodeCharSet(wordP.root.next);
    Set<Integer> All = getNodeCharSet(AllP.root.next);
    Set<Integer> noneWord = getNodeCharSet(noneWordP.root.next);
    /**
     * 用来生成一条ArrayList<Set<Integer>>的路径的字符串
     * @param path ArrayList<Set<Integer>>格式的路径
     * @return 形如“[a,b,c],[d]”的字符串，每个set用"[]"包裹，set之间用","分割
     */
    private String printPath (ArrayList<Set<Integer>> path, boolean mermaid) {
        String result = "";

        int indexP = 0;
        if (path.size() == 0) {
            return "null";
        }
        for (Set<Integer> s : path) {
            if (indexP != 0) {
                result += ",";
            }
            result += "[";
            if (setsEquals(s, Dot)) {
                result += ".";
            } else if (setsEquals(s, Bound)) {
                result += "\\b";
            } else if (setsEquals(s, Space)) {
                result += "\\s";
            } else if (setsEquals(s, noneSpace)) {
                result += "\\S";
            } else if (setsEquals(s, word)) {
                result += "\\w";
            } else if (setsEquals(s, All)) {
                result += "\\s\\S";
            } else if (s.size() > 20) {
                result += "size(" + s.size() + ")";
            }
            else {
                int indexS = 0;
                for (int i : s) {
                    if (indexS != 0) {
                        result += ",";
                    }
                    indexS++;
                    // System.out.print((char) i);
                    result += int2String(i, mermaid);
                }
            }
            result += "]";
        }
        return result;
    }

    /**
     * 用于判断两个set内容是否相同
     * @param set1
     * @param set2
     * @return 内容相同返回true，内容不同返回false
     */
    public boolean setsEquals(Set<?> set1, Set<?> set2) {
        //null就直接不比了
        if (set1 == null || set2 == null) {
            return false;
        }
        //大小不同也不用比了
        if (set1.size() != set2.size()) {
            return false;
        }
        //最后比containsAll
        return set1.containsAll(set2);
    }

    /**
     * 获得一个“实际字符”节点所有全部chaSet
     * @param node CharProperty、Slice、BnM类型的字符节点
     * @return 所有出现在节点中的字符的集合
     */
    private Set<Integer> getNodeCharSet(Pattern.Node node) {
        if (node instanceof Pattern.CharProperty) {
            if (((Pattern.CharProperty) node).charSet.size() == 0) {
                generateRawCharSet((Pattern.CharProperty) node);
            }
            return ((Pattern.CharProperty) node).charSet;
        } else if (node instanceof Pattern.SliceNode || node instanceof Pattern.BnM) {
            Set<Integer> charSet = new HashSet<>();
            for (int i : ((Pattern.SliceNode) node).buffer) {
                charSet.add(i);
            }
            return charSet;
        } else {
            return null;
        }
    }

    /**
     * 生成原本应该被节点接受的全部字符集合
     * @param root CharProperty类型的节点
     */
    private void generateRawCharSet(Pattern.CharProperty root) {
        // 默认的处理方法
        for (int i = 0; i < 65536 && !Thread.currentThread().isInterrupted(); i++) {
            if (root.isSatisfiedBy(i)) {
                root.charSet.add(i);
            }
        }
    }
}
