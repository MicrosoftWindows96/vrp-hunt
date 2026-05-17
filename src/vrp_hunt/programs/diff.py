"""Diff bug bounty program registries for fresh scope changes."""

from __future__ import annotations

from typing import Literal

from vrp_hunt.programs.models import (
    ProgramExclusion,
    ProgramProfile,
    ProgramRegistry,
    ProgramRegistryChange,
    ProgramRegistryDiff,
    ProgramScopeEntry,
)

EntryChange = Literal["added", "removed", "changed"]
DiffEntryType = Literal["scope", "exclusion"]


def diff_program_registries(
    old_registry: ProgramRegistry,
    new_registry: ProgramRegistry,
) -> ProgramRegistryDiff:
    """Compare two registries and identify fresh in-scope target additions."""

    changes: list[ProgramRegistryChange] = []
    old_programs = {program.id: program for program in old_registry.programs}
    new_programs = {program.id: program for program in new_registry.programs}

    for program_id in sorted(old_programs.keys() - new_programs.keys()):
        program = old_programs[program_id]
        changes.append(
            ProgramRegistryChange(
                change="removed",
                entry_type="program",
                program_id=program.id,
                program_name=program.name,
                old=_program_snapshot(program),
            )
        )

    for program_id in sorted(new_programs.keys() - old_programs.keys()):
        program = new_programs[program_id]
        changes.append(
            ProgramRegistryChange(
                change="added",
                entry_type="program",
                program_id=program.id,
                program_name=program.name,
                new=_program_snapshot(program),
            )
        )

    for program_id in sorted(old_programs.keys() & new_programs.keys()):
        old_program = old_programs[program_id]
        new_program = new_programs[program_id]
        if _program_snapshot(old_program) != _program_snapshot(new_program):
            changes.append(
                ProgramRegistryChange(
                    change="changed",
                    entry_type="program",
                    program_id=program_id,
                    program_name=new_program.name,
                    old=_program_snapshot(old_program),
                    new=_program_snapshot(new_program),
                )
            )
        changes.extend(_diff_scope_entries(old_program, new_program))
        changes.extend(_diff_exclusions(old_program, new_program))

    fresh_targets = [
        change
        for change in changes
        if change.entry_type == "scope" and change.fresh_target
    ]
    return ProgramRegistryDiff(
        old_version=old_registry.version,
        new_version=new_registry.version,
        changes=changes,
        fresh_targets=fresh_targets,
    )


def _diff_scope_entries(
    old_program: ProgramProfile,
    new_program: ProgramProfile,
) -> list[ProgramRegistryChange]:
    return _diff_entries(
        old_entries=old_program.scope,
        new_entries=new_program.scope,
        old_program=old_program,
        new_program=new_program,
        entry_type="scope",
    )


def _diff_exclusions(
    old_program: ProgramProfile,
    new_program: ProgramProfile,
) -> list[ProgramRegistryChange]:
    return _diff_entries(
        old_entries=old_program.exclusions,
        new_entries=new_program.exclusions,
        old_program=old_program,
        new_program=new_program,
        entry_type="exclusion",
    )


def _diff_entries(
    *,
    old_entries: list[ProgramScopeEntry] | list[ProgramExclusion],
    new_entries: list[ProgramScopeEntry] | list[ProgramExclusion],
    old_program: ProgramProfile,
    new_program: ProgramProfile,
    entry_type: DiffEntryType,
) -> list[ProgramRegistryChange]:
    changes: list[ProgramRegistryChange] = []
    old_by_id = {entry.id: entry for entry in old_entries}
    new_by_id = {entry.id: entry for entry in new_entries}

    for entry_id in sorted(old_by_id.keys() - new_by_id.keys()):
        entry = old_by_id[entry_id]
        changes.append(
            _entry_change(
                change="removed",
                entry_type=entry_type,
                program=old_program,
                entry=entry,
                old=_entry_snapshot(entry),
            )
        )

    for entry_id in sorted(new_by_id.keys() - old_by_id.keys()):
        entry = new_by_id[entry_id]
        changes.append(
            _entry_change(
                change="added",
                entry_type=entry_type,
                program=new_program,
                entry=entry,
                new=_entry_snapshot(entry),
                fresh_target=_is_fresh_added_scope(entry_type, entry),
            )
        )

    for entry_id in sorted(old_by_id.keys() & new_by_id.keys()):
        old_entry = old_by_id[entry_id]
        new_entry = new_by_id[entry_id]
        old_snapshot = _entry_snapshot(old_entry)
        new_snapshot = _entry_snapshot(new_entry)
        if old_snapshot == new_snapshot:
            continue
        changes.append(
            _entry_change(
                change="changed",
                entry_type=entry_type,
                program=new_program,
                entry=new_entry,
                old=old_snapshot,
                new=new_snapshot,
                fresh_target=_is_fresh_changed_scope(entry_type, old_entry, new_entry),
            )
        )
    return changes


def _entry_change(
    *,
    change: EntryChange,
    entry_type: DiffEntryType,
    program: ProgramProfile,
    entry: ProgramScopeEntry | ProgramExclusion,
    old: dict[str, object] | None = None,
    new: dict[str, object] | None = None,
    fresh_target: bool = False,
) -> ProgramRegistryChange:
    return ProgramRegistryChange(
        change=change,
        entry_type=entry_type,
        program_id=program.id,
        program_name=program.name,
        entry_id=entry.id,
        kind=entry.kind,
        value=entry.value,
        reward_eligible=entry.reward_eligible if isinstance(entry, ProgramScopeEntry) else None,
        source_reference=entry.source_reference,
        fresh_target=fresh_target,
        old=old,
        new=new,
    )


def _is_fresh_added_scope(
    entry_type: DiffEntryType,
    entry: ProgramScopeEntry | ProgramExclusion,
) -> bool:
    return entry_type == "scope" and isinstance(entry, ProgramScopeEntry) and entry.reward_eligible


def _is_fresh_changed_scope(
    entry_type: DiffEntryType,
    old_entry: ProgramScopeEntry | ProgramExclusion,
    new_entry: ProgramScopeEntry | ProgramExclusion,
) -> bool:
    if entry_type != "scope":
        return False
    if not isinstance(old_entry, ProgramScopeEntry) or not isinstance(new_entry, ProgramScopeEntry):
        return False
    became_reward_eligible = not old_entry.reward_eligible and new_entry.reward_eligible
    target_identity_changed = (
        old_entry.kind != new_entry.kind or old_entry.value.lower() != new_entry.value.lower()
    )
    return new_entry.reward_eligible and (became_reward_eligible or target_identity_changed)


def _program_snapshot(program: ProgramProfile) -> dict[str, object]:
    data = program.model_dump(mode="json", exclude={"scope", "exclusions"})
    return dict(data)


def _entry_snapshot(entry: ProgramScopeEntry | ProgramExclusion) -> dict[str, object]:
    return dict(entry.model_dump(mode="json"))
