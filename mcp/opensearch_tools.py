import json
from fastmcp import FastMCP
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mcp_client import get_client

mcp=FastMCP("Opensearch MCP Server")


@mcp.tool()
def get_index_mapping(index_name:str)->str:
    """Get the mapping of an index"""
    try : 
        client=get_client()
        mapping=client.indices.get_mapping(index=index_name)
        return json.dumps(mapping,indent=2)
    except Exception as e:
        return f"Error getting index mapping: {str(e)}"


'''@mcp.tool()
def Search_index(query_json:str,index_name:str="wazuh-archive",size:int=10)->str:

    try:
        client=get_client()
        query=json.loads(query_json)
        response = client.search(
            index=index_name,
            body=query,
            size=size
        )
        hits = response.get("hits", {})
        return json.dumps(hits, indent=2)
    except json.JSONDecodeError as e:
        return f"Error parsing query_json. Please provide a valid JSON string. Error: {str(e)}"
    except Exception as e:
        return f"Error executing search on index '{index_name}': {str(e)}"
        '''
@mcp.tool()
def msearch_tool(queries_json: list[str], index_name: str = "wazuh-archive") -> str:
    """
    Execute multiple OpenSearch queries at once (Multi-Search) to gather deep context.
    Agent: Use this tool to run multiple DSL queries simultaneously against the archives.
    
    Args:
        queries_json: A list of valid JSON strings, where each string is an OpenSearch query body.
        index_name: The target index. Defaults to 'wazuh-archives-*'.
    """
    try:
        client = get_client()
        body = []
        for q_str in queries_json:
            query = json.loads(q_str)
            # msearch requires pairs of {"index": index_name} and the actual query body
            body.append({"index": index_name})
            body.append(query)
            
        response = client.msearch(body=body)
        
        # Extract just the hits from each response to reduce context bloat
        results = [resp.get("hits", {}) for resp in response.get("responses", [])]
        return json.dumps(results, indent=2)
        
    except json.JSONDecodeError as e:
        return f"Error parsing a query in queries_json. Error: {str(e)}"
    except Exception as e:
        return f"Error executing msearch: {str(e)}"