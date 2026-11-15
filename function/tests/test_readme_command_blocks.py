"""README code blocks never preview a change and make it in the same paste.

GitHub shows a "Copy code to clipboard" button on every fenced code block, and
a shell runs each line of a multi-line paste as its own command. A block that
holds a -WhatIf preview and the same command without -WhatIf, or a deployer run
both without and with an enable switch, therefore makes the change before the
preview can be read.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[2]
README = LAB_ROOT / "README.md"

FENCE = "`" * 3
FENCED_BLOCK = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
ANY_FENCE_LINE = re.compile(r"^[ \t]*(?:`{3,}|~{3,})", re.MULTILINE)
# PowerShell (`) and shell (\) line continuations.
LINE_CONTINUATION = re.compile(r"[`\\]\n\s*")
WHATIF = re.compile(r"\s+-WhatIf\b", re.IGNORECASE)
INVOCATION = re.compile(r"^(?:pwsh (?:-\w+ )*|& ?)?(\S+)")
DEPLOYER_RUN = re.compile(r"^(?:pwsh (?:-\w+ )*|& ?)?\S*\bDeploy-\w+\.ps1\b")
ENABLE_SWITCH = re.compile(r"\s-Enable\w*\b", re.IGNORECASE)

DESTROY_PREVIEW = './scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -DestroyAzureResources -WhatIf'
DESTROY_RUN = './scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -DestroyAzureResources'


def fenced_command_blocks(markdown: str) -> list[tuple[int, list[str]]]:
    """Return (line of the opening fence, commands) for each fenced block.

    Line continuations are joined, comments and blank lines are dropped, and
    spacing is collapsed, so a wrapped command compares equal to the same
    command written on one line.
    """
    source = markdown.replace("\r\n", "\n")
    blocks = []
    for match in FENCED_BLOCK.finditer(source):
        joined = LINE_CONTINUATION.sub(" ", match.group(1))
        commands = [" ".join(line.split()) for line in joined.split("\n")]
        commands = [line for line in commands if line and not line.startswith("#")]
        blocks.append((source.count("\n", 0, match.start()) + 1, commands))
    return blocks


def invoked(command: str) -> str:
    """Name of the script or cmdlet a command runs, without its folder."""
    match = INVOCATION.match(command)
    token = match.group(1).strip("'\"") if match else command
    return re.split(r"[\\/]", token)[-1].lower()


def single_paste_problems(markdown: str, name: str = "README.md") -> list[str]:
    """Blocks whose one paste would run a change before its preview is read."""
    problems = []
    for line, commands in fenced_command_blocks(markdown):
        for preview in (command for command in commands if WHATIF.search(command)):
            # The real command, or any other run of the same script without
            # -WhatIf, would start as soon as the preview finished.
            runs = [
                command
                for command in commands
                if not WHATIF.search(command) and invoked(command) == invoked(preview)
            ]
            if runs:
                problems.append(f"{name}:{line}: one code block previews `{preview}` and also runs `{runs[0]}`")
        deployer_runs = [command for command in commands if DEPLOYER_RUN.match(command)]
        enabling = [command for command in deployer_runs if ENABLE_SWITCH.search(command)]
        if enabling and len(enabling) != len(deployer_runs):
            problems.append(
                f"{name}:{line}: one code block runs a deployer without an enable switch "
                f"and also runs `{enabling[0]}`"
            )
    return problems


def preview_order_problems(markdown: str, name: str = "README.md") -> list[str]:
    """A block that runs a previewed command must come after the preview."""
    blocks = fenced_command_blocks(markdown)
    problems = []
    for index, (line, commands) in enumerate(blocks):
        for preview in (command for command in commands if WHATIF.search(command)):
            real = WHATIF.sub("", preview, count=1)
            for earlier_line, earlier in blocks[:index]:
                if real in earlier:
                    problems.append(
                        f"{name}:{earlier_line}: `{real}` runs before its preview at line {line}"
                    )
    return problems


def page(*blocks: str) -> str:
    """Markdown with one short lead-in and one PowerShell block per argument."""
    return "".join(f"Lead-in:\n\n{FENCE}powershell\n{block}\n{FENCE}\n\n" for block in blocks)


class CommandBlockCheckerTests(unittest.TestCase):
    """The checker itself, on small pages with known answers."""

    def test_continuations_are_joined_and_comments_dropped(self) -> None:
        source = page(
            "# A comment that mentions -WhatIf is not a command.\n"
            './scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" `\n'
            "  -DestroyAzureResources    -WhatIf\n"
            "\n"
            "az group show \\\n"
            "  --name zsp-lab-rg"
        )
        self.assertEqual(
            fenced_command_blocks(source),
            [(3, [DESTROY_PREVIEW, "az group show --name zsp-lab-rg"])],
        )
        self.assertEqual(fenced_command_blocks(source.replace("\n", "\r\n")), fenced_command_blocks(source))

    def test_the_previous_full_cleanup_block_is_refused(self) -> None:
        # The block README.md held at line 693 until November 14, 2026.
        problems = single_paste_problems(page(f"{DESTROY_PREVIEW}\n{DESTROY_RUN}"))
        self.assertEqual(len(problems), 1)
        self.assertIn(f"previews `{DESTROY_PREVIEW}` and also runs `{DESTROY_RUN}`", problems[0])

    def test_a_wrapped_preview_or_another_run_of_the_same_script_is_refused(self) -> None:
        wrapped = (
            './scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" `\n'
            "  -DestroyAzureResources -WhatIf\n"
            f"{DESTROY_RUN}"
        )
        other_arguments = (
            './scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -WhatIf\n'
            '.\\scripts\\Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -DestroyAzureResources'
        )
        real_first = f"{DESTROY_RUN}\n{DESTROY_PREVIEW}"
        for block in (wrapped, other_arguments, real_first):
            with self.subTest(block=block):
                self.assertEqual(len(single_paste_problems(page(block))), 1)

    def test_a_deployer_run_with_and_without_an_enable_switch_is_refused(self) -> None:
        # Deploy-Lab.ps1 has no enable switch today; this keeps a future one,
        # like the Sentinel labs' -EnableRules, out of the first deployment's paste.
        deploy = './scripts/Deploy-Lab.ps1 -ConfirmLifecycleMigration -ProjectName "zsp-lab"'
        for switch in ("-EnableRules", "-EnableSentinelRules"):
            with self.subTest(switch=switch):
                problems = single_paste_problems(page(f"{deploy}\n{deploy} {switch}"))
                self.assertEqual(len(problems), 1)
                self.assertIn(f"also runs `{deploy} {switch}`", problems[0])
                self.assertEqual(single_paste_problems(page(deploy, f"{deploy} {switch}")), [])
        self.assertEqual(single_paste_problems(page(f"pwsh {deploy} -EnableRules")), [])

    def test_split_blocks_with_the_preview_first_pass(self) -> None:
        split = page(DESTROY_PREVIEW, DESTROY_RUN)
        self.assertEqual(single_paste_problems(split), [])
        self.assertEqual(preview_order_problems(split), [])
        reversed_order = preview_order_problems(page(DESTROY_RUN, DESTROY_PREVIEW))
        self.assertEqual(len(reversed_order), 1)
        self.assertIn("runs before its preview", reversed_order[0])

    def test_a_preview_whose_real_command_stays_in_a_comment_passes(self) -> None:
        block = (
            "./scripts/Remove-LegacyGraphGrants.ps1 -FunctionAppPrincipalId '<object-guid>' `\n"
            "  -AssignmentIds @('<reviewed-assignment-id>') -WhatIf\n"
            "# Remove -WhatIf only after reviewing the exact selected legacy assignments."
        )
        self.assertEqual(single_paste_problems(page(block)), [])


class ReadmeCommandBlockTests(unittest.TestCase):
    """The repository README, checked as a whole."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = README.read_text(encoding="utf-8")
        cls.blocks = fenced_command_blocks(cls.readme)

    def test_no_block_runs_a_previewed_command_or_an_enabling_rerun(self) -> None:
        self.assertEqual(single_paste_problems(self.readme), [])

    def test_every_previewed_command_is_shown_after_its_preview(self) -> None:
        self.assertEqual(preview_order_problems(self.readme), [])

    def test_the_checker_reads_every_block_and_finds_the_previews(self) -> None:
        # Every fence line must open or close a block the parser read, so an
        # indented or ~~~ fence cannot hide a block from the checks above.
        self.assertEqual(len(ANY_FENCE_LINE.findall(self.readme)), 2 * len(self.blocks))
        previews = [command for _, commands in self.blocks for command in commands if WHATIF.search(command)]
        self.assertGreaterEqual(len(previews), 3, previews)
        self.assertGreaterEqual(sum(invoked(command) == "cleanup-lab.ps1" for command in previews), 2, previews)

    def test_full_cleanup_is_previewed_in_its_own_block_before_it_runs(self) -> None:
        previews = [line for line, commands in self.blocks if commands == [DESTROY_PREVIEW]]
        runs = [line for line, commands in self.blocks if commands == [DESTROY_RUN]]
        self.assertEqual(len(previews), 1, f"expected one block holding only `{DESTROY_PREVIEW}`")
        self.assertEqual(len(runs), 1, f"expected one block holding only `{DESTROY_RUN}`")
        self.assertLess(previews[0], runs[0], "the full-cleanup preview must come before the full cleanup")


if __name__ == "__main__":
    unittest.main()
