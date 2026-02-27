"""
Security Agent — LangChain ReAct agent with memory and tool orchestration.

Demonstrates:
  • ReAct (Reasoning + Acting) agent pattern with chain-of-thought
  • ConversationBufferMemory for multi-turn context
  • Tool orchestration across reconnaissance, research, exploitation, reporting
  • Custom prompt template with few-shot examples
  • Structured output generation via tools
"""

from __future__ import annotations

from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_classic.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI

from agent.prompts import FEW_SHOT_EXAMPLES, REACT_TEMPLATE, SYSTEM_PROMPT
from agent.tools import ALL_TOOLS


def build_agent(
    target_url: str,
    model: str = "gpt-4o",
    temperature: float = 0.0,
    verbose: bool = True,
) -> AgentExecutor:
    """
    Construct and return a fully configured ReAct security agent.

    Parameters
    ----------
    target_url : str
        Base URL of the vulnerable target (e.g. http://localhost:8080).
    model : str
        OpenAI model name.
    temperature : float
        Sampling temperature (0 = deterministic).
    verbose : bool
        Whether to print intermediate reasoning steps.
    """
    llm = ChatOpenAI(model=model, temperature=temperature)

    prompt = PromptTemplate(
        template=REACT_TEMPLATE,
        input_variables=["input", "agent_scratchpad"],
        partial_variables={
            "system": SYSTEM_PROMPT,
            "few_shot": FEW_SHOT_EXAMPLES,
        },
    )

    memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True,
    )

    agent = create_react_agent(llm=llm, tools=ALL_TOOLS, prompt=prompt)

    executor = AgentExecutor(
        agent=agent,
        tools=ALL_TOOLS,
        memory=memory,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=25,
        return_intermediate_steps=True,
    )

    return executor


def run_assessment(target_url: str, **kwargs) -> dict:
    """Run a full security assessment against the target and return results."""
    executor = build_agent(target_url, **kwargs)

    task = (
        f"Perform a comprehensive security assessment of the web application "
        f"at {target_url}. Follow the methodology: reconnaissance, vulnerability "
        f"research, testing, exploitation, and reporting. Discover all endpoints, "
        f"identify vulnerabilities (especially Shellshock / CVE-2014-6271 patterns "
        f"and SQL injection), exploit them to prove impact, and generate a "
        f"structured report with your findings."
    )

    result = executor.invoke({"input": task})

    return {
        "output": result.get("output", ""),
        "intermediate_steps": result.get("intermediate_steps", []),
        "memory": memory_to_list(executor.memory),
    }


def memory_to_list(memory: ConversationBufferMemory) -> list[dict]:
    """Extract memory contents as a serialisable list."""
    messages = memory.chat_memory.messages
    return [{"type": type(m).__name__, "content": m.content} for m in messages]
