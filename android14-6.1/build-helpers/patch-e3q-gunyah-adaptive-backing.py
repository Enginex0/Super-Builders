#!/usr/bin/env python3
"""Apply after the immutable Gunyah helper chain; preserve ABI and parcel limits."""
from pathlib import Path
import argparse

MARKER = "GH_EXTENT_ADAPTIVE_BACKING_V1"


def replace_once(source, old, new):
    count = source.count(old)
    if count != 1:
        raise ValueError(f"expected one source anchor ({count} found): {old[:100]!r}")
    return source.replace(old, new, 1)


def validate(source):
    required = (
        "#define GH_EXTENT_ABI_MIN_PAGES 8UL",
        "#define GH_EXTENT_LIMIT 8192UL",
        "#define GH_EXTENT_MAX_ORDER 6U",
        "static unsigned int gh_extent_required_order(",
        "DIV_ROUND_UP(remaining, slots)",
        "min_order = gh_extent_required_order(remaining, slots);",
        "(1UL << min_order) > remaining",
        "gh_extent_alloc_buddy(remaining, min_order, &order)",
        "gh_extent_alloc_contig(remaining, min_order, &order)",
        "buf->chunk_capacity = min(nr_pages, GH_EXTENT_LIMIT);",
        "DIV_ROUND_UP(nr_pages, GH_EXTENT_ABI_MIN_PAGES) > GH_EXTENT_LIMIT",
        "buf->nr_chunks >= GH_EXTENT_LIMIT",
        "__free_page(nth_page(chunk->base, i));",
        "__free_pages(chunk->base, chunk->order);",
        "vm_map_pages_zero(vma, buf->pages, nr_pages)",
        "allocated adaptive bounded backing",
        "return -E2BIG;",
        MARKER,
    )
    for token in required:
        if token not in source:
            raise ValueError(f"adaptive backing postcondition missing: {token}")
    for token in ("GH_EXTENT_MIN_ORDER", "GH_EXTENT_MIN_PAGES",
                  "free_contig_range(page_to_pfn(chunk->base), nr_pages)"):
        if token in source:
            raise ValueError(f"obsolete/unsafe backing token remains: {token}")
    if source.count("try_order > min_order") != 2:
        raise ValueError("both allocation paths must obey the request-specific order")
    if source.count("try_order == min_order") != 2:
        raise ValueError("both allocation paths must stop at the bounded minimum")


def transform(source):
    if MARKER in source:
        validate(source)
        return source
    # Require the completed immutable chain, including its reference-safe teardown.
    if "__free_page(nth_page(chunk->base, i));" not in source:
        raise ValueError("run the existing metadata/QCOM helper chain first")
    source = replace_once(source, "#define GH_EXTENT_MIN_ORDER 3U",
                          f"/* {MARKER}: ABI bounds unchanged; order follows extent budget. */\n"
                          "#define GH_EXTENT_ABI_MIN_PAGES 8UL")
    source = replace_once(source, "#define GH_EXTENT_MIN_PAGES (1UL << GH_EXTENT_MIN_ORDER)\n", "")
    start = source.index(" * Keep every physical run at least order-3")
    end = source.index(" */", start)
    source = source[:start] + (
        " * Preserve the original request-size ABI and 8192 physical-run bound.\n"
        " * Prefer large buddy chunks, but permit smaller chunks when the remaining\n"
        " * page/extent budget allows them. This avoids rejecting a 128 MiB guest\n"
        " * solely because 32 KiB chunks are unavailable. Normal GUP and the\n"
        " * reference-safe buddy/contiguous teardown remain unchanged.\n"
    ) + source[end:]
    helper = """/* The caller rejects zero slots before this calculation. */
static unsigned int gh_extent_required_order(unsigned long remaining,
                                             unsigned long slots)
{
\tunsigned long pages_per_slot = DIV_ROUND_UP(remaining, slots);
\tunsigned int order = 0;

\twhile ((1UL << order) < pages_per_slot && order < GH_EXTENT_MAX_ORDER)
\t\torder++;
\treturn order;
}

"""
    source = replace_once(source,
        "static struct page *gh_extent_alloc_buddy(unsigned long remaining,\n",
        helper + "static struct page *gh_extent_alloc_buddy(unsigned long remaining,\n"
        "\t\t\t\t\t unsigned int min_order,\n")
    source = replace_once(source,
        "static struct page *gh_extent_alloc_contig(unsigned long remaining,\n",
        "static struct page *gh_extent_alloc_contig(unsigned long remaining,\n"
        "\t\t\t\t\t  unsigned int min_order,\n")
    if source.count("try_order > GH_EXTENT_MIN_ORDER") != 2 or source.count("try_order == GH_EXTENT_MIN_ORDER") != 2:
        raise ValueError("unexpected buddy/contiguous fallback loop shape")
    source = source.replace("try_order > GH_EXTENT_MIN_ORDER", "try_order > min_order")
    source = source.replace("try_order == GH_EXTENT_MIN_ORDER", "try_order == min_order")
    source = replace_once(source, "\t\tunsigned int order = GH_EXTENT_MIN_ORDER;",
        "\t\tunsigned long slots;\n\t\tunsigned int min_order, order;")
    source = replace_once(source,
        "\t\tbase = gh_extent_alloc_buddy(remaining, &order);",
        """\t\tif (buf->nr_chunks >= buf->chunk_capacity ||
\t\t    buf->nr_chunks >= GH_EXTENT_LIMIT)
\t\t\treturn -E2BIG;
\t\tslots = buf->chunk_capacity - buf->nr_chunks;
\t\tif (DIV_ROUND_UP(remaining, slots) > (1UL << GH_EXTENT_MAX_ORDER))
\t\t\treturn -E2BIG;
\t\tmin_order = gh_extent_required_order(remaining, slots);
\t\tif ((1UL << min_order) > remaining)
\t\t\treturn -E2BIG;
\t\torder = min_order;

\t\tbase = gh_extent_alloc_buddy(remaining, min_order, &order);""")
    source = replace_once(source, "gh_extent_alloc_contig(remaining, &order)",
                          "gh_extent_alloc_contig(remaining, min_order, &order)")
    source = replace_once(source, "buf->contig_chunks, GH_EXTENT_MIN_ORDER);",
                          "buf->contig_chunks, min_order);")
    source = replace_once(source,
        "allocated bounded backing pages=%lu chunks=%lu buddy=%lu contig=%lu max_extents=%lu min_order=%u max_order=%u",
        "allocated adaptive bounded backing pages=%lu chunks=%lu buddy=%lu contig=%lu max_extents=%lu max_order=%u")
    source = replace_once(source, "\t\tGH_EXTENT_MIN_ORDER, GH_EXTENT_MAX_ORDER);",
                          "\t\tGH_EXTENT_MAX_ORDER);")
    source = source.replace("GH_EXTENT_MIN_PAGES", "GH_EXTENT_ABI_MIN_PAGES")
    source = replace_once(source,
        "buf->chunk_capacity = DIV_ROUND_UP(nr_pages, GH_EXTENT_ABI_MIN_PAGES);",
        "buf->chunk_capacity = min(nr_pages, GH_EXTENT_LIMIT);")
    validate(source)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_tree", type=Path)
    args = parser.parse_args()
    directory = args.kernel_tree / "drivers/virt/gunyah"
    source_path = directory / "cma_compat.c"
    vm_source = (directory / "vm_mgr.c").read_text()
    if vm_source.count("mapping->parcel.n_mem_entries > 8192") != 1:
        raise SystemExit("ERROR: expected exactly one existing 8192 parcel guard")
    original = source_path.read_text()
    try:
        result = transform(original)
    except ValueError as error:
        raise SystemExit(f"ERROR: adaptive backing source preflight: {error}") from error
    if result != original:
        source_path.write_text(result)
    print("Gunyah adaptive backing V1 verified: ABI size bound unchanged; "
          "8192 chunk/parcel bounds and reference-safe teardown preserved")


if __name__ == "__main__":
    main()
