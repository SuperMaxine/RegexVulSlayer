package regex;

import redos.regex.Pattern4Search;
import redos.regex.redosPattern;

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

    private final boolean OneCouting = true;
    private final boolean POA = false;
    private final boolean SLQ = false;

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

    public Analyzer(String regex, int maxLength) {
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

        // 记录开始时间
        long startTime = System.currentTimeMillis();
        //  建立原始树
        Pattern rawPattern = Pattern.compile(regex);
        root = buildTree(rawPattern.root, new HashSet<>());
        // System.out.println("flowchart TD");
        // printTree(root, true);
        // 对原始树进行优化，生成新树
        root = buildFinalTree(root);
        // 生成所有字符集，生成字符集只改变了Pattern.Node的charSet，并没有改变tree中LeafNode的path，还需注意
        generateAllBigCharSet();
        // System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        // printTree(root, true);
        // 对新树生成所有路径
        // 生成路径操作一定要在确认所有字符集都生成完毕之后再进行
        generateAllPath(root);
        System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        printTree(root, true);
        // 记录结束时间
        long endTime = System.currentTimeMillis();
        System.out.println("Build tree cost time: " + (endTime - startTime) + "ms");

        // --------------------生成树阶段结束，对漏洞进行攻击阶段开始-----------------------------

        // 生成前缀路径
        for (LeafNode node : countingNodes) {
            ArrayList<ArrayList<Set<Integer>>> prePaths = generatePrePath(node);
            Collections.sort((prePaths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
            countingPrePaths.put(node, prePaths);
            // System.out.println("\n" + node.toString());
            // System.out.println(printPaths(prePaths, false));
            // Enumerator pre = new Enumerator(prePaths.get(0));
            // while(pre.hasNext()) {
            //     System.out.println(pre.next());
            // }
        }

        if (OneCouting) {
            for (LeafNode node : countingNodes) {
                for (int i = 0 ; i < node.paths.size() ; i++) {
                    for (int j = i + 1; j < node.paths.size(); j++) {
                        ArrayList<Set<Integer>> pumpPath = getPathTotalOverLap(node.paths.get(i), node.paths.get(j));
                        if(pumpPath.size() != 0) {
                            for (ArrayList<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                Enumerator preEnum = new Enumerator(prePath);
                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                if (dynamicValidate(preEnum, pumpEnum, VulType.OneCounting)) return;
                            }
                        }
                    }
                }
            }
        }
    }

    enum VulType {
        OneCounting, POA, SLQ
    }

    private boolean dynamicValidate(Enumerator preEnum, Enumerator pumpEnum, VulType type) {
        int max_length = 50;
        if (type == VulType.OneCounting) {
            max_length = 50;
        } else if (type == VulType.POA) {
            max_length = 10000;
        } else if (type == VulType.SLQ) {
            max_length = 30000;
        }

        // 如果前缀可空的话，前缀固定为""，只枚举后缀
        if (preEnum.Empty()) {
            while (pumpEnum.hasNext()) {
                String pump = pumpEnum.next();
                double matchingStepCnt;
                if (type == VulType.SLQ) matchingStepCnt = testPattern4Search.getMatchingStepCnt("", pump, "\n\b\n", max_length, 100000);
                else matchingStepCnt = testPattern.getMatchingStepCnt("", pump, "\n\b\n", max_length, 100000);
                // System.out.println(matchingStepCnt);
                if (matchingStepCnt > 1e5) {
                    System.out.println(matchingStepCnt);
                    attackable = true;
                    attackMsg = type + "\nprefix:\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                    return true;
                }
                // System.out.println("");
            }
        }
        // 如果前缀不可空的话，前缀和中缀组合枚举
        else {
            while (preEnum.hasNext()) {
                String pre = preEnum.next();
                while (pumpEnum.hasNext()) {
                    String pump = pumpEnum.next();
                    double matchingStepCnt;
                    if (type == VulType.SLQ) matchingStepCnt = testPattern4Search.getMatchingStepCnt(pre, pump, "\n\b\n", max_length, 100000);
                    else matchingStepCnt = testPattern.getMatchingStepCnt(pre, pump, "\n\b\n", max_length, 100000);
                    // System.out.println(matchingStepCnt);
                    if (matchingStepCnt > 1e5) {
                        // System.out.println("matchingStepCnt > 1e5");
                        System.out.println(matchingStepCnt);
                        attackable = true;
                        attackMsg = type + "\nprefix:" + pre + "\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                        return true;
                    }
                }
            }
        }

        return false;
    }

    ArrayList<Set<Integer>> getPathTotalOverLap(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2) {
        ArrayList<Set<Integer>> result = new ArrayList<>();
        // 如果两条path的长度不同，则不可能有完全重叠
        if (path1.size() != path2.size()) {
            return result;
        }
        else {
            // 如果两个路径的长度相同，则需要比较每一个节点的字符集
            ArrayList<Set<Integer>> charSet1 = new ArrayList<>();
            for (int i = 0; i < path1.size(); i++) {
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
            for (int i = 0; i < path.size(); i++) {
                this.path.add(new ArrayList<>(path.get(i)));
                this.indexs.add(0);
            }
        }

        public String next() {
            String sb = "";
            for (int i = 0; i < path.size(); i++) {
                int tmp = path.get(i).get(indexs.get(i));
                sb += (char) tmp;
            }

            for (int i = indexs.size() - 1; i >= 0; i--) {
                // 如果这一位的index遍历到头，则重置这一位，进入下一轮循环让下一位进位
                if (indexs.get(i) == path.get(i).size()) {
                    indexs.set(i, 0);
                    continue;
                } else {
                    // 如果这一位的index还没有遍历到头，让这一位的index加1
                    indexs.set(i, indexs.get(i) + 1);
                    // 如果这一位经过加1遍历到头的话，重置这一位，给前一位加1
                    for (int j = i; j > 0 && indexs.get(j) == path.get(j).size(); j--) {
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
            for (int i = 0; i < this.indexs.size(); i++) {
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

        LeafNode (Set<Integer> groupNums) {
            this.groupNums = new HashSet<Integer>(groupNums);
            this.paths = new ArrayList<>();
        }

        LeafNode copy(LeafNode father) {
            LeafNode result = new LeafNode(new HashSet<>());
            result.paths = new ArrayList<>(this.paths);
            result.actualNode = actualNode;
            result.father = father;
            return result;
        }

        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    +printPaths(paths, true)+"\"]");
        }
    }

    // 能够连接其他节点的类拓展自LinkNode
    private abstract class LinkNode extends LeafNode {
        LinkNode(Set<Integer> groupNums) {
            super(groupNums);
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
            super(groupNums);
            this.left = left;
            this.right = right;

            if (left != null) left.father = this;
            if (right != null) right.father = this;
        }

        /**
         * 根据左右子树路径生成本节点的路径
         */
        void generatePaths() {
            leftPaths = new ArrayList<>();
            rightPaths = new ArrayList<>();

            if (left != null && !(left instanceof LookaroundNode)) leftPaths.addAll(left.paths);
            if (right != null && !(right instanceof LookaroundNode)) rightPaths.addAll(right.paths);

            if (leftPaths.size() == 0) {
                this.paths.addAll(rightPaths);
            }
            else if (rightPaths.size() == 0) {
                this.paths.addAll(leftPaths);
            }
            else {
                for (ArrayList<Set<Integer>> leftPath : leftPaths) {
                    for (ArrayList<Set<Integer>> rightPath : rightPaths) {
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

            Collections.sort((this.paths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
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
            return node == left;
        }

        boolean comeFromRight(LeafNode node) {
            return node == right;
        }

        ArrayList<ArrayList<Set<Integer>>> returnTrueLeftPaths() {
            ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
            if (!(left instanceof LookaroundNode)) result.addAll(left.paths);
            return result;
        }

        ArrayList<ArrayList<Set<Integer>>> returnTrueRightPaths() {
            ArrayList<ArrayList<Set<Integer>>> result = new ArrayList<>();
            if (!(right instanceof LookaroundNode)) result.addAll(right.paths);
            return result;
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
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 分支结构
    private class BranchNode extends LinkNode {
        ArrayList<LeafNode> children;
        Map<LeafNode, ArrayList<ArrayList<Set<Integer>>>> childrenPaths;

        BranchNode (Pattern.Node actualNode, Set<Integer> groupNums) {
            super(groupNums);
            children = new ArrayList<>();
            childrenPaths = new HashMap<>();
            this.actualNode = actualNode;
        }

        void addChild (LeafNode child) {
            children.add(child);
            child.father = this;
        }

        void generatePaths() {
            for (LeafNode child : children) {
                childrenPaths.put(child, new ArrayList<>(child.paths));
                if (!(child instanceof LookaroundNode)) this.paths.addAll(child.paths);
            }
            Collections.sort((this.paths), new Comparator<ArrayList<Set<Integer>>>() {
                @Override
                public int compare(ArrayList<Set<Integer>> o1, ArrayList<Set<Integer>> o2) {
                    return o1.size() - o2.size();
                }
            });
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            for (int i = 0; i < children.size(); i++) {
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
            super(groupNums);
            this.cmin = cmin;
            this.cmax = cmax;
            this.atom = atom;
            if (atom != null) atom.father = this;
            this.actualNode = actualNode;
        }

        void generatePaths() {
            if (!(atom instanceof LookaroundNode)) this.atomPaths = new ArrayList<>(atom.paths);

            ArrayList<ArrayList<Set<Integer>>> lastPaths = new ArrayList<>();
            lastPaths.add(new ArrayList<>());

            for (int i = 0; i < cmin; i++) {
                ArrayList<ArrayList<Set<Integer>>> newPaths = new ArrayList<>();
                for (ArrayList<Set<Integer>> atomPath : atomPaths) {
                    for (ArrayList<Set<Integer>> lastPath : lastPaths) {
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
            for (int i = cmin; i < cmax && i < maxLength; i++) {
                this.paths.addAll(lastPaths);
                ArrayList<ArrayList<Set<Integer>>> newPaths = new ArrayList<>();
                for (ArrayList<Set<Integer>> atomPath : atomPaths) {
                    for (ArrayList<Set<Integer>> lastPath : lastPaths) {
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
                    + "cmin = " + cmin + "\\ncmax = " + cmax + "\\n"
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

        LookaroundNode(LeafNode atom, lookaroundType type, Set<Integer> groupNums) {
            super(groupNums);
            this.atom = atom;
            this.type = type;
            atom.father = this;
        }

        void generatePaths() {
            this.paths.addAll(atom.paths);
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            this.atom = newNode;
            if (newNode != null) newNode.father = this;
            this.paths = new ArrayList<>(newNode.paths);
        }

        @Override
        LookaroundNode copy(LeafNode father) {
            LookaroundNode result =  new LookaroundNode(null, type, new HashSet<>());
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + "type = " + type.toString() + "\\n"
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 反向引用
    private class BackRefNode extends LeafNode {
        int groupIndex;
        BackRefNode (int groupIndex, Set<Integer> groupNums) {
            super(groupNums);
            this.groupIndex = groupIndex;
        }

        @Override
        BackRefNode copy(LeafNode father) {
            BackRefNode result = new BackRefNode(groupIndex, new HashSet<>());
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + "groupIndex = " + groupIndex + "\\n"
                    + "localIndex = " + groupIndex2LocalIndex.get(groupIndex) + "\\n"
                    +(debug ? printPaths(paths, true) : "")+"\"]");
        }
    }

    // 整个正则的终止符节点
    private class LastNode extends LeafNode {
        LastNode (Pattern.Node lastNode, Set<Integer> groupNums) {
            super(groupNums);
            actualNode = lastNode;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_"));
        }
    }

    // "^"符号
    private class Begin extends LeafNode {
        Begin (Set<Integer> groupNums) {
            super(groupNums);
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "^" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    +"\"]");
        }
    }

    // "$"符号
    private class End extends LeafNode {
        End (Set<Integer> groupNums) {
            super(groupNums);
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "$" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
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
        while (node != this.root) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                result = splicePath(((ConnectNode) father).returnTrueLeftPaths(), result);
            }
            node = father;
        }
        if (result.size() == 0) result.add(new ArrayList<>());
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
                    if (prefixPath.size() + suffixPath.size() < maxLength) {
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
     * 对传入的树，递归地生成每一个节点的Path，同时记录每个循环节点
     * @param root 根节点
     */
    private void generateAllPath(LeafNode root) {
        if (root == null) {
            return;
        }
        else if (root instanceof LinkNode) {
            if (root instanceof ConnectNode) {
                generateAllPath(((ConnectNode) root).left);
                generateAllPath(((ConnectNode) root).right);
                ((ConnectNode) root).generatePaths();
            }
            else if (root instanceof BranchNode) {
                for (LeafNode node : ((BranchNode) root).children) {
                    generateAllPath(node);
                }
                ((BranchNode) root).generatePaths();
            }
            else if (root instanceof LoopNode) {
                generateAllPath(((LoopNode) root).atom);
                ((LoopNode) root).generatePaths();
                countingNodes.add(root);
            }
            else if (root instanceof LookaroundNode) {
                generateAllPath(((LookaroundNode) root).atom);
                ((LookaroundNode) root).generatePaths();
            }
        }
        else if (root instanceof LeafNode) {
            if (root.actualNode == null) {
                return;
            }
            else if (root.actualNode instanceof Pattern.CharProperty) {
                root.paths = new ArrayList<>();
                ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
                tmpPath.add(((Pattern.CharProperty) root.actualNode).charSet);
                root.paths.add(tmpPath);
            }
        }
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

        // 2. 判断是否在前部加入.{0,3}
        if (branchAtFirst(root) == 1) {
            // 在前部加入.{0,3}
            Pattern dotPattern = Pattern.compile(".{0,3}");
            LeafNode dotTree = buildTree(dotPattern.root, new HashSet<>());

            root = new ConnectNode(dotTree, root, new HashSet<>());
        }


        // 3. 是将结尾的lookaround拿出还是在尾部添加[\s\S]*
        // a. 如果结尾单独一个lookaround，则需要把lookaround拿出来缀在末尾
        searchLookaroundAtLast(root);
        if (lookaroundAtLast.size() == 1) {
            ((LinkNode)lookaroundAtLast.get(0).father).replaceChild(lookaroundAtLast.get(0), ((LookaroundNode)lookaroundAtLast.get(0)).atom);
        }
        // b. 如果结尾有多个连续的lookaround，则需要在结尾加上[\s\S]*
        if (lookaroundAtLast.size() > 1) {
            for (LeafNode node : lookaroundAtLast) {
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
            me = new BackRefNode(((Pattern.BackRef)root).groupIndex, groupNums);
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

            me = new LeafNode(groupNums);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            tmpPath.add(((Pattern.CharProperty) root).charSet);
            me.paths.add(tmpPath);
            me.actualNode = root;

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.SliceNode){
            me = new LeafNode(groupNums);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            for (int i : ((Pattern.SliceNode) root).buffer) {
                fullSmallCharSet.add(i);

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                tmpPath.add(tmpCharSet);
            }
            me.paths.add(tmpPath);
            me.actualNode = root;

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.BnM) {
            me = new LeafNode(groupNums);
            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
            for (int i : ((Pattern.BnM) root).buffer) {
                fullSmallCharSet.add(i);

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                tmpPath.add(tmpCharSet);
            }
            me.paths.add(tmpPath);
            me.actualNode = root;

            brother = buildTree(root.next, groupNums);
        }

        // lookaround处理
        else if (root instanceof Pattern.Pos){
            me = new LookaroundNode(buildTree(((Pattern.Pos)root).cond, groupNums), lookaroundType.Pos, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Neg){
            me = new LookaroundNode(buildTree(((Pattern.Neg)root).cond, groupNums), lookaroundType.Neg, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Behind){
            me = new LookaroundNode(buildTree(((Pattern.Behind)root).cond, groupNums), lookaroundType.Behind, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.NotBehind){
            me = new LookaroundNode(buildTree(((Pattern.NotBehind)root).cond, groupNums), lookaroundType.NotBehind, groupNums);
            brother = buildTree(root.next, groupNums);
        }

        // "^"、"$"
        else if (root instanceof Pattern.Begin || root instanceof Pattern.Caret || root instanceof Pattern.UnixCaret) {
            me = new Begin(groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Dollar || root instanceof Pattern.UnixDollar) {
            me = new End(groupNums);
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
        for (int i = 0; i < 65536; i++) {
            if (root.isSatisfiedBy(i)) {
                charSet.add(i);
            }
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
            Pattern.CharProperty root = (Pattern.CharProperty) entry.getKey();
            generateBigCharSet(root);
        }

    }

    /**
     * 压缩所有“大字符集”节点的charSet
     * @param root
     */
    private void generateBigCharSet(Pattern.CharProperty root) {
        Random rand = new Random();
        Set<Integer> result = new HashSet<>();

        // set2&set8
        Set<Integer> tmp;

        for (Map.Entry<Pattern.Node, Set<Integer>> entry : bigCharSetMap.entrySet()) {
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
                    if (entry_.getKey() == root || entry_.getKey() == entry.getKey()) {
                        continue;
                    } else {
                        tmp.removeAll(entry_.getValue());
                    }
                }

                if (tmp.size() > 0) {
                    int index = rand.nextInt(tmp.size());
                    Iterator<Integer> iter = tmp.iterator();
                    for (int i = 0; i < index; i++) {
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
            for (int i = 0; i < index; i++) {
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

        if (paths.size() > 30) result = "paths.size():"+paths.size()+(mermaid ? "\\n" : "\n");
        else {
            for (ArrayList<Set<Integer>> path : paths) {
                result += printPath(path);
                result += mermaid ? "\\n" : "\n";
            }
        }
        return result;
    }

    /**
     * 用来生成一条ArrayList<Set<Integer>>的路径的字符串
     * @param path ArrayList<Set<Integer>>格式的路径
     * @return 形如“[a,b,c],[d]”的字符串，每个set用"[]"包裹，set之间用","分割
     */
    private String printPath (ArrayList<Set<Integer>> path) {
        String result = "";
        //获取特定类别的节点set
        Set<Integer> Dot = getNodeCharSet(DotP.root.next);
        Set<Integer> Bound = getNodeCharSet(BoundP.root.next);
        Set<Integer> Space = getNodeCharSet(SpaceP.root.next);
        Set<Integer> noneSpace = getNodeCharSet(noneSpaceP.root.next);
        Set<Integer> word = getNodeCharSet(wordP.root.next);
        Set<Integer> All = getNodeCharSet(AllP.root.next);

        int indexP = 0;
        for (Set<Integer> s : path) {
            if (indexP != 0) {
                result += ",";
            }
            result += "[";
            if (equals(s, Dot)) {
                result += ".";
            } else if (equals(s, Bound)) {
                result += "\\b";
            } else if (equals(s, Space)) {
                result += "\\s";
            } else if (equals(s, noneSpace)) {
                result += "\\S";
            } else if (equals(s, word)) {
                result += "\\w";
            } else if (equals(s, All)) {
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
                    if (i == 10) {
                        result += "\\'n";
                    } else if (i == 13) {
                        result += "\\'r";
                    } else if (i == 34) {
                        result += "''";
                    } else {
                        result += (char) i;
                    }
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
    public boolean equals(Set<?> set1, Set<?> set2) {
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
        for (int i = 0; i < 65536; i++) {
            if (root.isSatisfiedBy(i)) {
                root.charSet.add(i);
            }
        }
    }
}
