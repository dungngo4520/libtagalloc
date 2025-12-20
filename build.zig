const std = @import("std");

const Import = struct { name: []const u8, module: *std.Build.Module };

fn addInstalledExe(
    b: *std.Build,
    name: []const u8,
    root_source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    import: ?Import,
    step_name: []const u8,
    step_desc: []const u8,
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
    const step = b.step(step_name, step_desc);
    step.dependOn(&install_exe.step);

    return step;
}

fn addInstalledCppExe(
    b: *std.Build,
    name: []const u8,
    root_source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tagalloc_lib: *std.Build.Step.Compile,
    step_name: []const u8,
    step_desc: []const u8,
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
    const step = b.step(step_name, step_desc);
    step.dependOn(&install_exe.step);

    return step;
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

    const demo_zig_step = addInstalledExe(
        b,
        "tagalloc-demo-zig",
        "examples/demo.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        "demo-zig",
        "Build tagalloc-demo-zig",
    );

    const demo_cpp_step = addInstalledCppExe(
        b,
        "tagalloc-demo-cpp",
        "examples/demo.cpp",
        target,
        optimize,
        tagalloc_lib,
        "demo-cpp",
        "Build tagalloc-demo-cpp",
    );

    const demo_step = b.step("demo", "Build all demos");
    demo_step.dependOn(demo_zig_step);
    demo_step.dependOn(demo_cpp_step);

    _ = addInstalledExe(
        b,
        "tagalloc-stress",
        "examples/stress.zig",
        target,
        optimize,
        .{ .name = "tagalloc", .module = root_mod },
        "stress",
        "Build tagalloc-stress",
    );

    addUnitTests(b, target, optimize, abi_mod);
}
