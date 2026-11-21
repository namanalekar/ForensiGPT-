import os
import json
from typing import Any
from google import genai
from google.genai import types
from app.core.config import settings
from app.ai.schemas import ForensicReportSchema
from app.ai.prompts import build_report_prompt, SYSTEM_INSTRUCTION_BASE
from app.reports.templates import OfflineReportBuilder

class GeminiForensicsClient:
    """
    Google Gemini Forensics AI Bridge.
    Uses the official google-genai SDK to generate structured forensic reports
    and answer evidence-grounded queries with strict schema validation and 1-retry fallback.
    """

    @classmethod
    def get_client(cls) -> genai.Client | None:
        api_key = settings.GEMINI_API_KEY.strip()
        if not api_key:
            return None
        return genai.Client(api_key=api_key)

    @classmethod
    def generate_report(
        cls,
        case_title: str,
        files: list[dict[str, Any]],
        analysis_map: dict[str, Any],
        sync_result: dict[str, Any] | None,
        risk_score: int,
        verdict: str,
        mode: str = "analyst",
        privacy_mode: bool = False
    ) -> tuple[ForensicReportSchema, str]:
        """
        Generates structured forensic report. If Privacy Mode is enabled or GEMINI_API_KEY
        is absent, generates deterministically offline via OfflineReportBuilder.
        """
        # Fallback to local template if Privacy Mode or no API key
        gemini_client = cls.get_client()
        if privacy_mode or not gemini_client:
            offline_schema = OfflineReportBuilder.generate_report(
                case_title=case_title,
                files=files,
                analysis_map=analysis_map,
                sync_result=sync_result,
                risk_score=risk_score,
                verdict=verdict,
                mode=mode
            )
            return offline_schema, "local_privacy_template"

        # Prepare evidence JSON
        evidence_payload = {
            "case_title": case_title,
            "deterministic_verdict": verdict,
            "computed_risk_score": risk_score,
            "files": files,
            "analysis_details": analysis_map,
            "correlation_sync": sync_result
        }
        evidence_json_str = json.dumps(evidence_payload, indent=2)
        system_prompt, user_prompt = build_report_prompt(evidence_json_str, mode=mode)
        model_name = settings.GEMINI_MODEL

        # Attempt structured output generation with 1-retry on schema failure
        for attempt in range(2):
            try:
                response = gemini_client.models.generate_content(
                    model=model_name,
                    contents=user_prompt if attempt == 0 else f"{user_prompt}\n\nRETRY DIRECTIVE: Previous response failed schema validation. Output strict JSON matching the schema.",
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ForensicReportSchema,
                        system_instruction=system_prompt,
                        temperature=0.2
                    )
                )

                # Parse JSON into Pydantic model
                report_dict = json.loads(response.text)
                validated_report = ForensicReportSchema.model_validate(report_dict)
                return validated_report, model_name
            except Exception as e:
                if attempt == 1:
                    # After 1 retry failure, fallback safely to deterministic template
                    fallback = OfflineReportBuilder.generate_report(
                        case_title=case_title,
                        files=files,
                        analysis_map=analysis_map,
                        sync_result=sync_result,
                        risk_score=risk_score,
                        verdict=verdict,
                        mode=mode
                    )
                    return fallback, f"fallback_after_error: {str(e)}"

        # Default fallback
        fallback = OfflineReportBuilder.generate_report(
            case_title=case_title,
            files=files,
            analysis_map=analysis_map,
            sync_result=sync_result,
            risk_score=risk_score,
            verdict=verdict,
            mode=mode
        )
        return fallback, "fallback"

    @classmethod
    def ask_the_evidence(
        cls,
        evidence_context: dict[str, Any],
        user_question: str,
        conversation_history: list[dict[str, str]]
    ) -> tuple[str, list[str]]:
        """
        Interactive Q&A grounded strictly in the stored evidence JSON.
        Refuses to speculate beyond the provided evidence.
        """
        gemini_client = cls.get_client()
        if not gemini_client:
            return (
                "Privacy Mode is active or GEMINI_API_KEY is not configured. "
                "Interactive AI queries require a valid API key.",
                []
            )

        evidence_str = json.dumps(evidence_context, indent=2)
        system_inst = (
            f"{SYSTEM_INSTRUCTION_BASE}\n\n"
            "STRICT GROUNDING DIRECTIVE:\n"
            "You are querying stored digital forensic evidence. You must answer the user's question "
            "ONLY using the facts and evidence IDs present in the <untrusted_evidence_data> block.\n"
            "If the evidence does not contain the answer, you MUST state: "
            "'The collected evidence does not contain information to answer this question.' "
            "Do not speculate or extrapolate beyond what is recorded."
        )

        user_content = f"""<untrusted_evidence_data>
{evidence_str}
</untrusted_evidence_data>

Investigator Query: {user_question}
"""
        try:
            resp = gemini_client.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_inst,
                    temperature=0.1
                )
            )
            # Find evidence citations in answer
            citations = re.findall(r'EVID-[A-Z0-9\-]+', resp.text)
            return resp.text, sorted(list(set(citations)))
        except Exception as e:
            return f"Error querying evidence: {str(e)}", []
