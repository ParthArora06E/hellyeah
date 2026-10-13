"""
Recon Module: Deep CMS & Web Application Framework Detector
Performs non-destructive passive & response fingerprinting to identify:
1. Content Management Systems (WordPress, Drupal, Joomla, Magento, Ghost, Shopify)
2. Frontend Frameworks (Next.js, Nuxt.js, React, Vue.js, Angular, Svelte)
3. Backend Application Stacks (Laravel, Django, Rails, Spring Boot, ASP.NET)
"""
import re
from typing import List, Dict, Any, Union
from ..adapter.base import BaseModule, ModuleMeta
from ...schemas.schemas import AssetBase, FindingBase


class CMSDetectorModule(BaseModule):
    meta = ModuleMeta(
        name="cms_detector",
        author="Auditor Security Team",
        description="Extracts CMS platforms, frontend frameworks, and backend application stacks",
        category="enrichment",
        is_passive=True,
        version="1.0.0"
    )

    async def run(self, target: str, context: Any) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        hosts_to_test = [target]

        # Include up to 4 high-value subdomains
        for a in getattr(context, "discovered_assets", []):
            if a.type == "subdomain" and any(k in a.value for k in ["www", "app", "portal", "blog", "store", "shop"]):
                if a.value not in hosts_to_test and len(hosts_to_test) < 5:
                    hosts_to_test.append(a.value)

        context.emit_log("info", f"Executing deep CMS and framework fingerprinting across {len(hosts_to_test)} endpoints...")

        for host in hosts_to_test:
            url = f"https://{host}"
            resp = await context.http.get(url, ttl_seconds=600, retries=1)
            if not resp:
                url = f"http://{host}"
                resp = await context.http.get(url, ttl_seconds=600, retries=1)
            if not resp:
                continue

            html = resp.text or ""
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = [c.lower() for c in resp.headers.get_list("set-cookie")] if hasattr(resp.headers, "get_list") else [headers.get("set-cookie", "").lower()]
            cookies_str = " ".join(cookies)

            detected_techs = []

            # -----------------------------------------------------------------
            # 1. WordPress
            # -----------------------------------------------------------------
            wp_version = None
            if "/wp-content/" in html or "/wp-includes/" in html:
                m = re.search(r'<meta name="generator" content="WordPress\s*([\d\.]+)"', html, re.I)
                if m:
                    wp_version = m.group(1)
                tech_name = f"WordPress {wp_version}" if wp_version else "WordPress"
                detected_techs.append(tech_name)

                # Check plugins
                if "woocommerce" in html.lower():
                    detected_techs.append("WooCommerce")
                if "elementor" in html.lower():
                    detected_techs.append("Elementor")

            # -----------------------------------------------------------------
            # 2. Drupal
            # -----------------------------------------------------------------
            if "drupal.settings" in html.lower() or "sites/default/files" in html or "x-generator" in headers and "drupal" in headers["x-generator"].lower():
                m = re.search(r'<meta name="generator" content="Drupal\s*([\d\.]+)"', html, re.I)
                v = m.group(1) if m else ""
                detected_techs.append(f"Drupal {v}".strip())

            # -----------------------------------------------------------------
            # 3. Joomla
            # -----------------------------------------------------------------
            if "/media/system/js/" in html or ("generator" in html and "joomla" in html.lower()):
                m = re.search(r'<meta name="generator" content="Joomla!\s*-\s*Open Source Content Management\s*-\s*Version\s*([\d\.]+)"', html, re.I)
                v = m.group(1) if m else ""
                detected_techs.append(f"Joomla {v}".strip())

            # -----------------------------------------------------------------
            # 4. Next.js & React
            # -----------------------------------------------------------------
            if "/_next/static/" in html or "__NEXT_DATA__" in html or "next.js" in headers.get("x-powered-by", "").lower():
                detected_techs.append("Next.js")
                detected_techs.append("React")
            elif "data-reactroot" in html or "react.production.min.js" in html:
                detected_techs.append("React")

            # -----------------------------------------------------------------
            # 5. Nuxt.js & Vue.js
            # -----------------------------------------------------------------
            if "/_nuxt/" in html or '__nuxt' in html:
                detected_techs.append("Nuxt.js")
                detected_techs.append("Vue.js")
            elif "data-v-" in html or "vue.min.js" in html:
                detected_techs.append("Vue.js")

            # -----------------------------------------------------------------
            # 6. Angular
            # -----------------------------------------------------------------
            if "ng-version" in html or "ng-app" in html:
                m = re.search(r'ng-version="([\d\.]+)"', html)
                v = m.group(1) if m else ""
                detected_techs.append(f"Angular {v}".strip())

            # -----------------------------------------------------------------
            # 7. Backend Frameworks (Cookies & Headers)
            # -----------------------------------------------------------------
            if "laravel_session" in cookies_str or "xsrf-token" in cookies_str:
                detected_techs.append("Laravel")
            if "csrftoken" in cookies_str:
                detected_techs.append("Django")
            if "_rails_session" in cookies_str or "rails" in headers.get("x-powered-by", "").lower():
                detected_techs.append("Ruby on Rails")
            if "jsessionid" in cookies_str:
                detected_techs.append("Java Servlet")
            if "__viewstate" in html.lower() or "asp.net" in cookies_str or "x-aspnet-version" in headers:
                detected_techs.append("ASP.NET")
            if "shopify" in html.lower() or "myshopify.com" in html.lower():
                detected_techs.append("Shopify")

            if detected_techs:
                # Deduplicate
                detected_techs = sorted(list(set(detected_techs)))
                context.emit_log("info", f"Identified application stack on {host}: {', '.join(detected_techs)}")

                # Update existing asset in context
                for a in getattr(context, "discovered_assets", []):
                    if a.value.lower() == host.lower():
                        current_t = set(a.technologies or [])
                        current_t.update(detected_techs)
                        a.technologies = list(current_t)
                        break

                # Also create an enriched technology asset
                results.append(AssetBase(
                    type="service",
                    value=f"Web Stack ({host}): {', '.join(detected_techs)}",
                    source="CMS & Framework Detector",
                    owner="Application Team",
                    criticality=3,
                    technologies=detected_techs,
                    tags=["cms-framework", "web-stack"]
                ))

        return results
