// RCE Orphan-Stitching Engine
// 复合型静态应用程序安全测试 (SAST) - Python 孤儿节点缝合引擎

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes._

@main def main(): Unit = {
    def jsonEscape(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    println("[*] Starting Phase 1 BFS Orphan-Stitching Engine for RCE...")


  // 1. 进化版的 trapA：精准捕获 URL Router 里的 Path Variables
  val trapA = cpg.typeDecl.name(".*(View|ViewSet|API|Controller|Handler).*")
                 .method.name("(?i)^(get|post|put|delete|patch|list|create|retrieve|update|destroy)$")
                 .parameter.filter(p => !Set("self", "cls", "request", "req", "*args", "**kwargs").contains(p.name)).l

  // 2. 最纯正的手动 HTTP 提取源 (Request, GET, POST, JSON 提取等)
  val trapB = cpg.method.parameter.name("(?i)^(request|req)$").l
  val trapC = cpg.call.name("(?i)^(args|form|values|cookies|get_argument|get_query_params|get_json|json|params|GET|POST|FILES|validated_data)$").filter { c =>
       c.argument.order(1).code.headOption.getOrElse("").matches("(?i).*(request|req|self|serializer).*")
  }.l

  // 3. 合并所有 Web 入口源
  val allSources = (trapA ++ trapB ++ trapC).distinct

  println("[*] Pre-computing Web Endpoints (预计算 Web 路由入口以实现极速匹配)...")
  val sourceMethodSet = scala.collection.mutable.Set[String]()
  allSources.foreach { src =>
    src match {
      case p: MethodParameterIn => sourceMethodSet.add(p.method.fullName)
      case c: Call => sourceMethodSet.add(c.method.fullName)
      case _ =>
    }
  }
  println(s"[+] Found ${sourceMethodSet.size} potential web entry points.")



  val sinkOs = cpg.call.name("(?i)^(system|popen|spawn.*|exec.*)$").filter(_.methodFullName.matches("(?i).*os.*")).argument.l
  val sinkSubprocess = cpg.call.name("(?i)^(run|Popen|call|check_call|check_output)$").filter(_.methodFullName.matches("(?i).*subprocess.*")).argument.l
  val sinkEvalExec = cpg.call.name("(?i)^(eval|exec)$").filter(_.code.matches("(?i)^(eval|exec)\\(.*")).argument.l
  val sinkPickle = cpg.call.name("(?i)^(loads|load|unpickle)$").filter(_.methodFullName.matches("(?i).*(pickle|yaml).*")).argument.l
  val sinkList = (sinkOs ++ sinkSubprocess ++ sinkEvalExec ++ sinkPickle).flatMap(_.method).distinct.l
  val sinkMethods = sinkList
    

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
            val callerParams = caller.parameter.filter(p => p.name != "this" && p.name != "self").l
            
            if (callerParams.isEmpty) return ("BROKEN", caller.fullName, caller.code)
            
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
