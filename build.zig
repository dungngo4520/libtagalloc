const std = @import("std");

const Import = struct { name: []const u8, module: *std.Build.Module };

fn addInstalledExe(
    b: *std.Build,
    name: []const u8,
    root_source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    import: ?Import,
    step_name: ?[]const u8,
    step_desc: ?[]const u8,
) *std.Build.Step {
    const exe_mod = b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
    });
    if (import) |imp| exe_mod.addImport(imp.name, imp.module);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = exe_mod,
    });

    const install_exe = b.addInstallArtifact(exe, .{});

    if (step_name) |sn| {
        const sd = step_desc orelse "Build";
        const step = b.step(sn, sd);
        step.dependOn(&install_exe.step);
        return step;
    }

    return &install_exe.step;
}

fn addInstalledCppExe(
    b: *std.Build,
    name: []const u8,
    root_source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tagalloc_lib: *std.Build.Step.Compile,
    step_name: ?[]const u8,
    step_desc: ?[]const u8,
) *std.Build.Step {
    const exe_mod = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = exe_mod,
    });

    exe.addCSourceFile(.{
        .file = b.path(root_source),
        .flags = &.{"-std=c++17"},
        .language = .cpp,
    });

    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkLibrary(tagalloc_lib);

    const install_exe = b.addInstallArtifact(exe, .{});

    if (step_name) |sn| {
        const sd = step_desc orelse "Build";
        const step = b.step(sn, sd);
        step.dependOn(&install_exe.step);
        return step;
    }

    return &install_exe.step;
}

fn addUnitTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    abi_mod: *std.Build.Module,
) void {
    const test_step = b.step("test", "Run library tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("abi", abi_mod);

    const unit_tests = b.addTest(.{ .root_module = test_mod });
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/abi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/libtagalloc.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.addImport("abi", abi_mod);

    const tagalloc_lib = b.addLibrary(.{
        .name = "tagalloc",
        .root_module = root_mod,
        .linkage = .static,
    });

    // Install the header next to the .a for simpler consumption.
    b.installLibFile("include/libtagalloc.h", "libtagalloc.h");
    b.installArtifact(tagalloc_lib);

    _ = addInstalledExe(
        b,
        "tagalloc-poolreader",
        "tools/poolreader.zig",
        target,
        optimize,
        .{ .name = "abi", .module = abi_mod },
        "poolreader",
        "Build tagalloc-poolreader",
    );

    const demo_zig_install = addInstalledExe(
        b,
        "tagalloc-demo-zig",
        "examples/demo.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        null,
        null,
    );

    const demo_cpp_install = addInstalledCppExe(
        b,
        "tagalloc-demo-cpp",
        "examples/demo.cpp",
        target,
        optimize,
        tagalloc_lib,
        null,
        null,
    );

    const demo_step = b.step("demo", "Build all demos");
    demo_step.dependOn(demo_zig_install);
    demo_step.dependOn(demo_cpp_install);

    const stress_step = addInstalledExe(
        b,
        "tagalloc-stress",
        "examples/stress.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        "stress",
        "Build tagalloc-stress",
    );

    const bench_slab_step = addInstalledExe(
        b,
        "tagalloc-bench-slab",
        "examples/bench_slab.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        "bench-slab",
        "Build tagalloc-bench-slab",
    );

    const fixture_step = addInstalledExe(
        b,
        "tagalloc-fixture",
        "examples/fixture.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        "fixture",
        "Build tagalloc-fixture",
    );

    const examples_step = b.step("examples", "Build all examples");
    examples_step.dependOn(demo_zig_install);
    examples_step.dependOn(demo_cpp_install);
    examples_step.dependOn(stress_step);
    examples_step.dependOn(bench_slab_step);
    examples_step.dependOn(fixture_step);

    // Alias: 'example' (singular) → 'examples' (plural) for convenience.
    const example_alias = b.step("example", "Build all examples (alias)");
    example_alias.dependOn(examples_step);

    addUnitTests(b, target, optimize, abi_mod);
}
