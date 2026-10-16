const std = @import("std");

fn add_command_executable(
    b: *std.Build,
    comptime name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    mod: *std.Build.Module,
) void {
    const exe = b.addExecutable(.{
        .name = "moxi-" ++ name,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/apps/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "moxi", .module = mod }},
        }),
    });
    b.installArtifact(exe);
}

fn add_test_binaries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const zig_helloworld_mod = b.createModule(.{
        .root_source_file = b.path("test/zig_helloworld/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{
                .name = "foo",
                .module = b.createModule(.{
                    .root_source_file = b.path("test/zig_helloworld/root.zig"),
                    .target = target,
                }),
            },
        },
    });

    const zig_libc_mod = b.createModule(.{
        .root_source_file = b.path("test/zig_helloworld/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{
                .name = "foo",
                .module = b.createModule(.{
                    .root_source_file = b.path("test/zig_helloworld/libc_root.zig"),
                    .target = target,
                }),
            },
        },
        .link_libc = true,
    });

    const zig_helloworld = b.addExecutable(.{
        .name = "zig_helloworld",
        .root_module = zig_helloworld_mod,
    });

    const zig_pie = b.addExecutable(.{
        .name = "zig_pie",
        .root_module = zig_helloworld_mod,
    });
    zig_pie.pie = true;

    const zig_libc = b.addExecutable(.{
        .name = "zig_libc",
        .root_module = zig_libc_mod,
    });

    const c_test = b.addExecutable(.{
        .name = "c_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    c_test.root_module.addCSourceFiles(.{
        .files = &.{"test/c_test.c"},
        .flags = &.{"-std=c17"},
    });
    c_test.pie = true;

    const test_binaries = [_]*std.Build.Step.Compile{
        zig_helloworld,
        zig_pie,
        zig_libc,
        c_test,
    };

    const test_binaries_step = b.step("testbinaries", "Build test executables");
    for (test_binaries) |test_binary| {
        test_binaries_step.dependOn(&b.addInstallArtifact(test_binary, .{}).step);
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const c_module = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    }).createModule();

    const mod = b.addModule("moxi", .{
        // Anything public in root.zig is accessible using Moxi as a library.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "c", .module = c_module },
        },
    });

    const daemon_exe = b.addExecutable(.{
        .name = "moxid",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/apps/daemon.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "moxi", .module = mod },
            },
        }),
    });

    daemon_exe.root_module.link_libc = true;
    daemon_exe.root_module.linkSystemLibrary("dw", .{});
    // TODO: Seemingly not actually needed so far.
    daemon_exe.root_module.linkSystemLibrary("elf", .{});

    add_command_executable(b, "start", target, optimize, mod);
    add_command_executable(b, "next", target, optimize, mod);
    add_command_executable(b, "breakpoint", target, optimize, mod);
    add_command_executable(b, "source", target, optimize, mod);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(daemon_exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    run_cmd.addPassthruArgs();

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = daemon_exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    add_test_binaries(b, target, optimize);
}
