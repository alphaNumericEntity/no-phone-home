import { parse, type DefaultTreeAdapterTypes } from "parse5";

type Node = DefaultTreeAdapterTypes.Node;
type Element = DefaultTreeAdapterTypes.Element;

export interface MetaPolicy {
  content: string;
  inHead: boolean;
  after?: string;
}

const LOADING_ELEMENTS: Record<string, string> = {
  script: "src",
  link: "href",
  img: "src",
  iframe: "src",
  video: "src",
  audio: "src",
  source: "src",
  embed: "src",
  object: "data",
};

const LOADING_LINK_RELS = new Set(["stylesheet", "preload", "modulepreload", "prefetch", "icon", "apple-touch-icon", "manifest", "preconnect", "dns-prefetch"]);

function loads(element: Element): boolean {
  if (element.tagName !== "link") return true;
  const rels = (attribute(element, "rel") ?? "").toLowerCase().split(/\s+/);
  return rels.some((rel) => LOADING_LINK_RELS.has(rel));
}

function isElement(node: Node): node is Element {
  return "tagName" in node;
}

function attribute(element: Element, name: string): string | undefined {
  return element.attrs.find((attr) => attr.name === name)?.value;
}

function describe(element: Element, attr: string, value: string): string {
  return `<${element.tagName} ${attr}="${value.length > 60 ? `${value.slice(0, 57)}...` : value}">`;
}

export function metaPolicies(html: string): MetaPolicy[] {
  const found: MetaPolicy[] = [];
  let firstLoad: string | undefined;

  const visit = (node: Node) => {
    if (isElement(node)) {
      if (node.tagName === "meta" && attribute(node, "http-equiv")?.trim().toLowerCase() === "content-security-policy") {
        const content = attribute(node, "content");
        if (content !== undefined) {
          const parent = node.parentNode;
          const inHead = parent !== null && isElement(parent) && parent.tagName === "head";
          found.push({ content, inHead, ...(firstLoad ? { after: firstLoad } : {}) });
        }
      }
      const loadAttr = LOADING_ELEMENTS[node.tagName];
      const value = loadAttr ? attribute(node, loadAttr) : undefined;
      if (!firstLoad && loadAttr && value && loads(node)) firstLoad = describe(node, loadAttr, value);
      if (node.tagName === "template") return;
    }
    if ("childNodes" in node) for (const child of node.childNodes) visit(child);
  };

  visit(parse(html));
  return found;
}
