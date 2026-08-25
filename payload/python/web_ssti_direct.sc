// SSTI Direct-Stitching Engine
// 复合型静态应用程序安全测试 (SAST) - Python 直通链路引擎

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes._

@main def main(): Unit = {
    def jsonEscape(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    println("[*] Starting Phase 0 Direct Dataflow Engine for SSTI...")


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



  val sinkFlask = cpg.call.methodFullName(".*render_template_string.*").argument.l
  val sinkJinja2 = cpg.call.methodFullName(".*jinja2.*from_string.*|.*jinja2\\.Template.*").argument.l
  val sinkMako = cpg.call.methodFullName(".*mako\\.template\\.Template.*").argument.l
  val sinkDjango = cpg.call.methodFullName(".*django\\.template\\.Template.*").argument.l
  val sinkAnsible = cpg.call.methodFullName("(?i).*(ansible_runner|runner)\\..*(run|apply|execute)$").argument.l
  val allSinks = (sinkFlask ++ sinkJinja2 ++ sinkMako ++ sinkDjango ++ sinkAnsible).distinct.l
    

    println(s"[+] Found ${allSinks.size} potential sink calls.")

    var totalFound = 0
    val visited = scala.collection.mutable.Set[String]()

    // 原生 DataFlow 引擎执行全局追踪
    val flows = allSinks.reachableByFlows(allSources).l
    for (flow <- flows) {
        val srcNode = flow.elements.head
        val sinkNode = flow.elements.last

        def getMethodFullName(n: AstNode): String = n match {
            case c: CfgNode => c.method.fullName
            case _ => "Unknown"
        }

        val callChainList = flow.elements.flatMap {
            case c: CfgNode => Some(c.method.fullName)
            case _ => None
        }.distinct.toList
        
        val pathString = callChainList.mkString(" -> ")
        val pairKey = s"${getMethodFullName(srcNode)}|${getMethodFullName(sinkNode)}"

        if (!visited.contains(pairKey)) {
            visited.add(pairKey)

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

            val chainMethodNodes = flow.elements.flatMap {
                case c: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => Some(c.method)
                case _ => None
            }.distinct.toList

            val chainNodesJson = buildChainNodesJson(chainMethodNodes)
            val sourceSnippet = jsonEscape(srcNode.code)
            val sinkSnippet = jsonEscape(sinkNode.code)

            val j = s"""{"source_component":"${jsonEscape(getMethodFullName(srcNode))}","sink_component":"${jsonEscape(getMethodFullName(sinkNode))}","call_chain":"${jsonEscape(pathString)}","chain_nodes":$chainNodesJson,"sast_status":"CONFIRMED","source_snippet":"$sourceSnippet","sink_snippet":"$sinkSnippet"}"""
            println(s"O_DIRECT>>$j")
            totalFound += 1
        }
    }

    println(s"[+] Phase 0 Direct Engine Completed. Found $totalFound direct paths.")
}
