// SQLI Orphan-Stitching Engine
// 复合型静态应用程序安全测试 (SAST) - Java 孤儿节点缝合引擎

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes._

@main def main(): Unit = {
    def jsonEscape(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    println("[*] Starting Phase 1 BFS Orphan-Stitching Engine for SQLI...")


    // 预计算所有的 Spring Controller API 端点，生成 O(1) 哈希集合
    println("[*] Pre-computing Web Endpoints (预计算 Web 路由入口以实现极速匹配)...")
    val sourceMethodSet = scala.collection.mutable.Set[String]()
    cpg.method.filter { m =>
        m.annotation.name(".*Mapping.*").nonEmpty || m.typeDecl.annotation.name(".*(Mapping|Path).*").nonEmpty
    }.foreach { m => sourceMethodSet.add(m.fullName) }
    println(s"[+] Found ${sourceMethodSet.size} potential web entry points.")



  val sinkRegex = ".*(?:(?:java\\.sql\\.(?:Statement|PreparedStatement|CallableStatement)\\.(?:execute|executeQuery|executeUpdate|executeBatch))|(?:org\\.springframework\\.jdbc\\.core\\.JdbcTemplate\\.(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|update|batchUpdate|execute))).*"
  val sinkMethods = cpg.call.methodFullName(sinkRegex).l.flatMap(_.method).distinct
    

    if (sinkMethods.isEmpty) {
        println("[-] No Sinks found in this project.")
        return
    }
    
    println(s"[+] Found ${sinkMethods.size} distinct sink methods. Starting Upward BFS Traverse...")

    def getCode(m: io.shiftleft.codepropertygraph.generated.nodes.Method): String = {
        val header = s"// ${m.filename}:${m.lineNumber.getOrElse("?")}"
        var c = m.code
        if (c == null || c.trim == "" || c == "<empty>") {
            val calls = m.ast.isCall.code.l
            if (calls.nonEmpty) c = calls.take(5).mkString("\n")
            else if (m.block.astChildren.nonEmpty) c = m.block.astChildren.code.l.mkString("\n")
            else c = s"File: ${m.filename}, Line: ${m.lineNumber.getOrElse("unknown")}"
        }
        header + "\n" + c
    }


    // 核心组件：Pair-Wise 数据流断点探测器
    def checkFlow(orderedPath: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): (String, String, String) = {
        if (orderedPath.size <= 1) return ("CONFIRMED", "", "")
        
        for (i <- 0 until orderedPath.size - 1) {
            val caller = orderedPath(i)
            val callee = orderedPath(i + 1)
            val safeTypes = Set(
                "int", "long", "boolean", "double", "float", "short", "byte", "char",
                "java.lang.Integer", "java.lang.Long", "java.lang.Boolean", "java.lang.Double",
                "java.lang.Float", "java.lang.Short", "java.lang.Byte", "java.lang.Character"
            )
            val excludeFramework = ".*(HttpServletResponse|Model|ModelAndView|ModelMap|BindingResult|Principal|Authentication|HttpSession|InputStream|OutputStream).*"
            
            val callerParams = caller.parameter.filter(p => 
                p.name != "this" && 
                !safeTypes.contains(p.typeFullName) && 
                !p.typeFullName.matches(excludeFramework)
            ).l
            
            if (callerParams.isEmpty) return ("REJECTED", caller.fullName, caller.code)
            
            val calls = caller.ast.isCall.filter(c => c.name == callee.name || c.methodFullName == callee.fullName).l
            if (calls.isEmpty) return ("BROKEN", caller.fullName, caller.code)
            
            val callArgs = calls.flatMap(_.argument.l)
            var isConnected = false
            
            for (p <- callerParams) {
                 if (!isConnected) {
                     val flows = callArgs.reachableBy(p).l
                     if (flows.nonEmpty) isConnected = true
                 }
            }
            if (!isConnected) return ("BROKEN", caller.fullName, caller.code)
        }
        return ("CONFIRMED", "", "")
    }


    def buildChainNodesJson(orderedPath: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): String = {
        orderedPath.zipWithIndex.map { case (m, i) =>
            val role = if (i == 0) "SOURCE" else if (i == orderedPath.size - 1) "SINK" else "MIDDLE"
            val sn = s"${m.typeDecl.name.headOption.getOrElse("Unk")}.${m.name}"
            val params = m.parameter.l.filter(p => p.name != "this" && p.name != "self").map { p =>
                val shortType = if (p.typeFullName.contains(".")) p.typeFullName.split("\\.").last else p.typeFullName
                s"$shortType ${p.name}"
            }.mkString(", ")
            val methodSignature = s"${m.name}(${params})"
            val callToNextNode = if (i < orderedPath.size - 1) {
                val callee = orderedPath(i + 1)
                m.ast.isCall.filter(c => c.name == callee.name || c.methodFullName == callee.fullName).headOption
            } else None
            val callToNextCode = callToNextNode.map(_.code).getOrElse("")
            val callToNextLine = callToNextNode.flatMap(_.lineNumber).getOrElse(-1)
            
            s"""{"order":$i,"role":"$role","full_name":"${jsonEscape(m.fullName)}","short_name":"${jsonEscape(sn)}","file":"${jsonEscape(m.filename)}","entry_line":${m.lineNumber.getOrElse(-1)},"method_signature":"${jsonEscape(methodSignature)}","call_to_next":"${jsonEscape(callToNextCode)}","call_to_next_line":$callToNextLine}"""
        }.mkString("[", ",", "]")
    }

    case class TraversalNode(
        method: io.shiftleft.codepropertygraph.generated.nodes.Method,
        depth: Int,
        path: List[io.shiftleft.codepropertygraph.generated.nodes.Method]
    )

    val queue = scala.collection.mutable.Queue[TraversalNode]()
    val visitedPaths = scala.collection.mutable.Set[String]()     // 防路径循环
    val visitedPairs = scala.collection.mutable.Set[String]()     // 端点对去重
    val visitedMethods = scala.collection.mutable.Set[String]()   // 【极致优化】：全局节点级去重防爆炸
    var totalStitched = 0

    sinkMethods.foreach { m =>
        queue.enqueue(TraversalNode(m, 0, List(m)))
        visitedMethods.add(m.fullName)
    }

    while (queue.nonEmpty) {
        val node = queue.dequeue()
        val currentMethod = node.method
        
        if (node.depth <= 20) {
            if (sourceMethodSet.contains(currentMethod.fullName)) {
                val pathString = node.path.reverse.map(m => s"${m.typeDecl.name.headOption.getOrElse("Unk")}.${m.name}").mkString(" -> ")
                if (!visitedPaths.contains(pathString)) {
                    visitedPaths.add(pathString)
                    val sourceMethod = node.path.last
                    val sinkMethod = node.path.head
                    val mappingStr = sourceMethod.annotation.name(".*Mapping.*").code.l.mkString(" ") 
                    val pairKey = s"${sourceMethod.fullName}|${sinkMethod.fullName}"
                    
                    if (!visitedPairs.contains(pairKey)) {
                        visitedPairs.add(pairKey)
                        val orderedPath = node.path.reverse
                        val (sastStatus, bpMethod, bpCode) = checkFlow(orderedPath)
                        
                        if (sastStatus != "REJECTED") {
                            val sourceSnippet = jsonEscape(getCode(sourceMethod))
                            val sinkSnippet   = jsonEscape(getCode(sinkMethod))
                            val chainNodesJson = buildChainNodesJson(orderedPath)

                            val j = s"""{"source_component":"${jsonEscape(sourceMethod.fullName)}","sink_component":"${jsonEscape(sinkMethod.fullName)}","call_chain":"${jsonEscape(pathString)}","chain_nodes":$chainNodesJson,"match_type":"CALLGRAPH_STITCH","mapping":"${jsonEscape(mappingStr)}","sast_status":"${sastStatus}","breakpoint_method":"${jsonEscape(bpMethod)}","breakpoint_code":"${jsonEscape(bpCode)}","source_snippet":"$sourceSnippet","sink_snippet":"$sinkSnippet"}"""
                            println(s"O_STITCH>>$j")
                            totalStitched += 1
                        }
                    }
                }
            } else {
                val callers = currentMethod.callIn.method.l
                if (callers.isEmpty) {
                     if (node.depth > 0) {
                        val pathString = node.path.reverse.map(m => s"${m.typeDecl.name.headOption.getOrElse("Unk")}.${m.name}").mkString(" -> ")
                        if (!visitedPaths.contains(pathString)) {
                            visitedPaths.add(pathString)
                            val sourceMethod = node.path.last
                            val sinkMethod = node.path.head
                            val pairKey = s"${sourceMethod.fullName}|${sinkMethod.fullName}"
                            
                            if (!visitedPairs.contains(pairKey)) {
                                visitedPairs.add(pairKey)
                                val orderedPath = node.path.reverse
                                
                                // 【极致优化】：免验孤儿，直接跳过耗时的 checkFlow
                                val sastStatus = "ORPHAN"
                                val bpMethod = ""
                                val bpCode = ""
                                
                                val sourceSnippet = jsonEscape(getCode(sourceMethod))
                                val sinkSnippet   = jsonEscape(getCode(sinkMethod))
                                val chainNodesJson = buildChainNodesJson(orderedPath)

                                val j = s"""{"source_component":"${jsonEscape(sourceMethod.fullName)}","sink_component":"${jsonEscape(sinkMethod.fullName)}","call_chain":"${jsonEscape(pathString)}","chain_nodes":$chainNodesJson,"match_type":"ORPHAN_STITCH","mapping":"","sast_status":"${sastStatus}","breakpoint_method":"${jsonEscape(bpMethod)}","breakpoint_code":"${jsonEscape(bpCode)}","source_snippet":"$sourceSnippet","sink_snippet":"$sinkSnippet"}"""
                                println(s"O_STITCH>>$j")
                                totalStitched += 1
                            }
                        }
                     }
                } else {
                    callers.foreach { caller =>
                        if (!visitedMethods.contains(caller.fullName)) {
                            visitedMethods.add(caller.fullName)
                            queue.enqueue(TraversalNode(caller, node.depth + 1, node.path :+ caller))
                        }
                    }
                }
            }
        }
    }
    println(s"[+] BFS Upward Traversal Completed. Total Endpoints/Orphans Stitched: $totalStitched")
}
