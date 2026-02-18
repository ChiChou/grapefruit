/**
 * ported from https://github.com/chame1eon/jnitrace-engine

MIT License

Copyright (c) 2019 chame1eon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

import Java from "frida-java-bridge";
// bug: capturing backtrace causes crashes in some apps, skip for now
// import { bt } from "@/common/hooks/context.js";
import { findGlobalExport } from "@/lib/polyfill.js";

export interface JNIEvent {
  subject: string;
  type: string;
  method: string;
  callType: string;
  threadId: number;
  args: string[];
  ret: string;
  library?: string;
}

export interface JNILog {
  id: number;
  timestamp: string;
  type: string;
  method: string;
  callType: string;
  threadId: number | null;
  args?: string[];
  ret: string | null;
  backtrace?: string[];
  library: string | null;
  createdAt: string;
}

interface MethodDef {
  name: string;
  args: string[];
  ret: string;
}

const subject = "jni";
let listeners: InvocationListener[] = [];
const tracingThreads = new Set<number>();
let active = false;

// JNIEnv function table
const JNI_ENV: MethodDef[] = [
  { name: "reserved0", args: [], ret: "void" },
  { name: "reserved1", args: [], ret: "void" },
  { name: "reserved2", args: [], ret: "void" },
  { name: "reserved3", args: [], ret: "void" },
  { name: "GetVersion", args: ["JNIEnv*"], ret: "jint" },
  {
    name: "DefineClass",
    args: ["JNIEnv*", "char*", "jobject", "jbyte*", "jsize"],
    ret: "jclass",
  },
  { name: "FindClass", args: ["JNIEnv*", "char*"], ret: "jclass" },
  {
    name: "FromReflectedMethod",
    args: ["JNIEnv*", "jobject"],
    ret: "jmethodID",
  },
  { name: "FromReflectedField", args: ["JNIEnv*", "jobject"], ret: "jfieldID" },
  {
    name: "ToReflectedMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "jboolean"],
    ret: "jobject",
  },
  { name: "GetSuperclass", args: ["JNIEnv*", "jclass"], ret: "jclass" },
  {
    name: "IsAssignableFrom",
    args: ["JNIEnv*", "jclass", "jclass"],
    ret: "jboolean",
  },
  {
    name: "ToReflectedField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jboolean"],
    ret: "jobject",
  },
  { name: "Throw", args: ["JNIEnv*", "jthrowable"], ret: "jint" },
  { name: "ThrowNew", args: ["JNIEnv*", "jclass", "char*"], ret: "jint" },
  { name: "ExceptionOccurred", args: ["JNIEnv*"], ret: "jthrowable" },
  { name: "ExceptionDescribe", args: ["JNIEnv*"], ret: "void" },
  { name: "ExceptionClear", args: ["JNIEnv*"], ret: "void" },
  { name: "FatalError", args: ["JNIEnv*", "char*"], ret: "void" },
  { name: "PushLocalFrame", args: ["JNIEnv*", "jint"], ret: "jint" },
  { name: "PopLocalFrame", args: ["JNIEnv*", "jobject"], ret: "jobject" },
  { name: "NewGlobalRef", args: ["JNIEnv*", "jobject"], ret: "jobject" },
  { name: "DeleteGlobalRef", args: ["JNIEnv*", "jobject"], ret: "void" },
  { name: "DeleteLocalRef", args: ["JNIEnv*", "jobject"], ret: "void" },
  {
    name: "IsSameObject",
    args: ["JNIEnv*", "jobject", "jobject"],
    ret: "jboolean",
  },
  { name: "NewLocalRef", args: ["JNIEnv*", "jobject"], ret: "jobject" },
  { name: "EnsureLocalCapacity", args: ["JNIEnv*", "jint"], ret: "jint" },
  { name: "AllocObject", args: ["JNIEnv*", "jclass"], ret: "jobject" },
  {
    name: "NewObject",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jobject",
  },
  {
    name: "NewObjectV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jobject",
  },
  {
    name: "NewObjectA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jobject",
  },
  { name: "GetObjectClass", args: ["JNIEnv*", "jobject"], ret: "jclass" },
  {
    name: "IsInstanceOf",
    args: ["JNIEnv*", "jobject", "jclass"],
    ret: "jboolean",
  },
  {
    name: "GetMethodID",
    args: ["JNIEnv*", "jclass", "char*", "char*"],
    ret: "jmethodID",
  },
  {
    name: "CallObjectMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jobject",
  },
  {
    name: "CallObjectMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jobject",
  },
  {
    name: "CallObjectMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jobject",
  },
  {
    name: "CallBooleanMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jboolean",
  },
  {
    name: "CallBooleanMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jboolean",
  },
  {
    name: "CallBooleanMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jboolean",
  },
  {
    name: "CallByteMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jbyte",
  },
  {
    name: "CallByteMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jbyte",
  },
  {
    name: "CallByteMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jbyte",
  },
  {
    name: "CallCharMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jchar",
  },
  {
    name: "CallCharMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jchar",
  },
  {
    name: "CallCharMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jchar",
  },
  {
    name: "CallShortMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jshort",
  },
  {
    name: "CallShortMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jshort",
  },
  {
    name: "CallShortMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jshort",
  },
  {
    name: "CallIntMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jint",
  },
  {
    name: "CallIntMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jint",
  },
  {
    name: "CallIntMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jint",
  },
  {
    name: "CallLongMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jlong",
  },
  {
    name: "CallLongMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jlong",
  },
  {
    name: "CallLongMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jlong",
  },
  {
    name: "CallFloatMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jfloat",
  },
  {
    name: "CallFloatMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jfloat",
  },
  {
    name: "CallFloatMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jfloat",
  },
  {
    name: "CallDoubleMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "jdouble",
  },
  {
    name: "CallDoubleMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "jdouble",
  },
  {
    name: "CallDoubleMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "jdouble",
  },
  {
    name: "CallVoidMethod",
    args: ["JNIEnv*", "jobject", "jmethodID", "..."],
    ret: "void",
  },
  {
    name: "CallVoidMethodV",
    args: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
    ret: "void",
  },
  {
    name: "CallVoidMethodA",
    args: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
    ret: "void",
  },
  {
    name: "CallNonvirtualObjectMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jobject",
  },
  {
    name: "CallNonvirtualObjectMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jobject",
  },
  {
    name: "CallNonvirtualObjectMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jobject",
  },
  {
    name: "CallNonvirtualBooleanMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jboolean",
  },
  {
    name: "CallNonvirtualBooleanMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jboolean",
  },
  {
    name: "CallNonvirtualBooleanMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jboolean",
  },
  {
    name: "CallNonvirtualByteMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jbyte",
  },
  {
    name: "CallNonvirtualByteMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jbyte",
  },
  {
    name: "CallNonvirtualByteMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jbyte",
  },
  {
    name: "CallNonvirtualCharMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jchar",
  },
  {
    name: "CallNonvirtualCharMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jchar",
  },
  {
    name: "CallNonvirtualCharMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jchar",
  },
  {
    name: "CallNonvirtualShortMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jshort",
  },
  {
    name: "CallNonvirtualShortMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jshort",
  },
  {
    name: "CallNonvirtualShortMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jshort",
  },
  {
    name: "CallNonvirtualIntMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jint",
  },
  {
    name: "CallNonvirtualIntMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jint",
  },
  {
    name: "CallNonvirtualIntMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jint",
  },
  {
    name: "CallNonvirtualLongMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jlong",
  },
  {
    name: "CallNonvirtualLongMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jlong",
  },
  {
    name: "CallNonvirtualLongMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jlong",
  },
  {
    name: "CallNonvirtualFloatMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jfloat",
  },
  {
    name: "CallNonvirtualFloatMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jfloat",
  },
  {
    name: "CallNonvirtualFloatMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jfloat",
  },
  {
    name: "CallNonvirtualDoubleMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "jdouble",
  },
  {
    name: "CallNonvirtualDoubleMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "jdouble",
  },
  {
    name: "CallNonvirtualDoubleMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "jdouble",
  },
  {
    name: "CallNonvirtualVoidMethod",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
    ret: "void",
  },
  {
    name: "CallNonvirtualVoidMethodV",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
    ret: "void",
  },
  {
    name: "CallNonvirtualVoidMethodA",
    args: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
    ret: "void",
  },
  {
    name: "GetFieldID",
    args: ["JNIEnv*", "jclass", "char*", "char*"],
    ret: "jfieldID",
  },
  {
    name: "GetObjectField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jobject",
  },
  {
    name: "GetBooleanField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jboolean",
  },
  {
    name: "GetByteField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jbyte",
  },
  {
    name: "GetCharField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jchar",
  },
  {
    name: "GetShortField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jshort",
  },
  {
    name: "GetIntField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jint",
  },
  {
    name: "GetLongField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jlong",
  },
  {
    name: "GetFloatField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jfloat",
  },
  {
    name: "GetDoubleField",
    args: ["JNIEnv*", "jobject", "jfieldID"],
    ret: "jdouble",
  },
  {
    name: "SetObjectField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jobject"],
    ret: "void",
  },
  {
    name: "SetBooleanField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jboolean"],
    ret: "void",
  },
  {
    name: "SetByteField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jbyte"],
    ret: "void",
  },
  {
    name: "SetCharField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jchar"],
    ret: "void",
  },
  {
    name: "SetShortField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jshort"],
    ret: "void",
  },
  {
    name: "SetIntField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jint"],
    ret: "void",
  },
  {
    name: "SetLongField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jlong"],
    ret: "void",
  },
  {
    name: "SetFloatField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jfloat"],
    ret: "void",
  },
  {
    name: "SetDoubleField",
    args: ["JNIEnv*", "jobject", "jfieldID", "jdouble"],
    ret: "void",
  },
  {
    name: "GetStaticMethodID",
    args: ["JNIEnv*", "jclass", "char*", "char*"],
    ret: "jmethodID",
  },
  {
    name: "CallStaticObjectMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jobject",
  },
  {
    name: "CallStaticObjectMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jobject",
  },
  {
    name: "CallStaticObjectMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jobject",
  },
  {
    name: "CallStaticBooleanMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jboolean",
  },
  {
    name: "CallStaticBooleanMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jboolean",
  },
  {
    name: "CallStaticBooleanMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jboolean",
  },
  {
    name: "CallStaticByteMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jbyte",
  },
  {
    name: "CallStaticByteMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jbyte",
  },
  {
    name: "CallStaticByteMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jbyte",
  },
  {
    name: "CallStaticCharMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jchar",
  },
  {
    name: "CallStaticCharMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jchar",
  },
  {
    name: "CallStaticCharMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jchar",
  },
  {
    name: "CallStaticShortMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jshort",
  },
  {
    name: "CallStaticShortMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jshort",
  },
  {
    name: "CallStaticShortMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jshort",
  },
  {
    name: "CallStaticIntMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jint",
  },
  {
    name: "CallStaticIntMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jint",
  },
  {
    name: "CallStaticIntMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jint",
  },
  {
    name: "CallStaticLongMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jlong",
  },
  {
    name: "CallStaticLongMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jlong",
  },
  {
    name: "CallStaticLongMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jlong",
  },
  {
    name: "CallStaticFloatMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jfloat",
  },
  {
    name: "CallStaticFloatMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jfloat",
  },
  {
    name: "CallStaticFloatMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jfloat",
  },
  {
    name: "CallStaticDoubleMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "jdouble",
  },
  {
    name: "CallStaticDoubleMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "jdouble",
  },
  {
    name: "CallStaticDoubleMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "jdouble",
  },
  {
    name: "CallStaticVoidMethod",
    args: ["JNIEnv*", "jclass", "jmethodID", "..."],
    ret: "void",
  },
  {
    name: "CallStaticVoidMethodV",
    args: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
    ret: "void",
  },
  {
    name: "CallStaticVoidMethodA",
    args: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
    ret: "void",
  },
  {
    name: "GetStaticFieldID",
    args: ["JNIEnv*", "jclass", "char*", "char*"],
    ret: "jfieldID",
  },
  {
    name: "GetStaticObjectField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jobject",
  },
  {
    name: "GetStaticBooleanField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jboolean",
  },
  {
    name: "GetStaticByteField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jbyte",
  },
  {
    name: "GetStaticCharField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jchar",
  },
  {
    name: "GetStaticShortField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jshort",
  },
  {
    name: "GetStaticIntField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jint",
  },
  {
    name: "GetStaticLongField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jlong",
  },
  {
    name: "GetStaticFloatField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jfloat",
  },
  {
    name: "GetStaticDoubleField",
    args: ["JNIEnv*", "jclass", "jfieldID"],
    ret: "jdouble",
  },
  {
    name: "SetStaticObjectField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jobject"],
    ret: "void",
  },
  {
    name: "SetStaticBooleanField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jboolean"],
    ret: "void",
  },
  {
    name: "SetStaticByteField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jbyte"],
    ret: "void",
  },
  {
    name: "SetStaticCharField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jchar"],
    ret: "void",
  },
  {
    name: "SetStaticShortField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jshort"],
    ret: "void",
  },
  {
    name: "SetStaticIntField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jint"],
    ret: "void",
  },
  {
    name: "SetStaticLongField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jlong"],
    ret: "void",
  },
  {
    name: "SetStaticFloatField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jfloat"],
    ret: "void",
  },
  {
    name: "SetStaticDoubleField",
    args: ["JNIEnv*", "jclass", "jfieldID", "jdouble"],
    ret: "void",
  },
  { name: "NewString", args: ["JNIEnv*", "jchar*", "jsize"], ret: "jstring" },
  { name: "GetStringLength", args: ["JNIEnv*", "jstring"], ret: "jsize" },
  {
    name: "GetStringChars",
    args: ["JNIEnv*", "jstring", "jboolean*"],
    ret: "jchar*",
  },
  {
    name: "ReleaseStringChars",
    args: ["JNIEnv*", "jstring", "jchar*"],
    ret: "void",
  },
  { name: "NewStringUTF", args: ["JNIEnv*", "char*"], ret: "jstring" },
  { name: "GetStringUTFLength", args: ["JNIEnv*", "jstring"], ret: "jsize" },
  {
    name: "GetStringUTFChars",
    args: ["JNIEnv*", "jstring", "jboolean*"],
    ret: "char*",
  },
  {
    name: "ReleaseStringUTFChars",
    args: ["JNIEnv*", "jstring", "char*"],
    ret: "void",
  },
  { name: "GetArrayLength", args: ["JNIEnv*", "jarray"], ret: "jsize" },
  {
    name: "NewObjectArray",
    args: ["JNIEnv*", "jsize", "jclass", "jobject"],
    ret: "jobjectArray",
  },
  {
    name: "GetObjectArrayElement",
    args: ["JNIEnv*", "jobjectArray", "jsize"],
    ret: "jobject",
  },
  {
    name: "SetObjectArrayElement",
    args: ["JNIEnv*", "jobjectArray", "jsize", "jobject"],
    ret: "void",
  },
  { name: "NewBooleanArray", args: ["JNIEnv*", "jsize"], ret: "jbooleanArray" },
  { name: "NewByteArray", args: ["JNIEnv*", "jsize"], ret: "jbyteArray" },
  { name: "NewCharArray", args: ["JNIEnv*", "jsize"], ret: "jcharArray" },
  { name: "NewShortArray", args: ["JNIEnv*", "jsize"], ret: "jshortArray" },
  { name: "NewIntArray", args: ["JNIEnv*", "jsize"], ret: "jintArray" },
  { name: "NewLongArray", args: ["JNIEnv*", "jsize"], ret: "jlongArray" },
  { name: "NewFloatArray", args: ["JNIEnv*", "jsize"], ret: "jfloatArray" },
  { name: "NewDoubleArray", args: ["JNIEnv*", "jsize"], ret: "jdoubleArray" },
  {
    name: "GetBooleanArrayElements",
    args: ["JNIEnv*", "jbooleanArray", "jboolean*"],
    ret: "jboolean*",
  },
  {
    name: "GetByteArrayElements",
    args: ["JNIEnv*", "jbyteArray", "jboolean*"],
    ret: "jbyte*",
  },
  {
    name: "GetCharArrayElements",
    args: ["JNIEnv*", "jcharArray", "jboolean*"],
    ret: "jchar*",
  },
  {
    name: "GetShortArrayElements",
    args: ["JNIEnv*", "jshortArray", "jboolean*"],
    ret: "jshort*",
  },
  {
    name: "GetIntArrayElements",
    args: ["JNIEnv*", "jintArray", "jboolean*"],
    ret: "jint*",
  },
  {
    name: "GetLongArrayElements",
    args: ["JNIEnv*", "jlongArray", "jboolean*"],
    ret: "jlong*",
  },
  {
    name: "GetFloatArrayElements",
    args: ["JNIEnv*", "jfloatArray", "jboolean*"],
    ret: "jfloat*",
  },
  {
    name: "GetDoubleArrayElements",
    args: ["JNIEnv*", "jdoubleArray", "jboolean*"],
    ret: "jdouble*",
  },
  {
    name: "ReleaseBooleanArrayElements",
    args: ["JNIEnv*", "jbooleanArray", "jboolean*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseByteArrayElements",
    args: ["JNIEnv*", "jbyteArray", "jbyte*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseCharArrayElements",
    args: ["JNIEnv*", "jcharArray", "jchar*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseShortArrayElements",
    args: ["JNIEnv*", "jshortArray", "jshort*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseIntArrayElements",
    args: ["JNIEnv*", "jintArray", "jint*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseLongArrayElements",
    args: ["JNIEnv*", "jlongArray", "jlong*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseFloatArrayElements",
    args: ["JNIEnv*", "jfloatArray", "jfloat*", "jint"],
    ret: "void",
  },
  {
    name: "ReleaseDoubleArrayElements",
    args: ["JNIEnv*", "jdoubleArray", "jdouble*", "jint"],
    ret: "void",
  },
  {
    name: "GetBooleanArrayRegion",
    args: ["JNIEnv*", "jbooleanArray", "jsize", "jsize", "jboolean*"],
    ret: "void",
  },
  {
    name: "GetByteArrayRegion",
    args: ["JNIEnv*", "jbyteArray", "jsize", "jsize", "jbyte*"],
    ret: "void",
  },
  {
    name: "GetCharArrayRegion",
    args: ["JNIEnv*", "jcharArray", "jsize", "jsize", "jchar*"],
    ret: "void",
  },
  {
    name: "GetShortArrayRegion",
    args: ["JNIEnv*", "jshortArray", "jsize", "jsize", "jshort*"],
    ret: "void",
  },
  {
    name: "GetIntArrayRegion",
    args: ["JNIEnv*", "jintArray", "jsize", "jsize", "jint*"],
    ret: "void",
  },
  {
    name: "GetLongArrayRegion",
    args: ["JNIEnv*", "jlongArray", "jsize", "jsize", "jlong*"],
    ret: "void",
  },
  {
    name: "GetFloatArrayRegion",
    args: ["JNIEnv*", "jfloatArray", "jsize", "jsize", "jfloat*"],
    ret: "void",
  },
  {
    name: "GetDoubleArrayRegion",
    args: ["JNIEnv*", "jdoubleArray", "jsize", "jsize", "jdouble*"],
    ret: "void",
  },
  {
    name: "SetBooleanArrayRegion",
    args: ["JNIEnv*", "jbooleanArray", "jsize", "jsize", "jboolean*"],
    ret: "void",
  },
  {
    name: "SetByteArrayRegion",
    args: ["JNIEnv*", "jbyteArray", "jsize", "jsize", "jbyte*"],
    ret: "void",
  },
  {
    name: "SetCharArrayRegion",
    args: ["JNIEnv*", "jcharArray", "jsize", "jsize", "jchar*"],
    ret: "void",
  },
  {
    name: "SetShortArrayRegion",
    args: ["JNIEnv*", "jshortArray", "jsize", "jsize", "jshort*"],
    ret: "void",
  },
  {
    name: "SetIntArrayRegion",
    args: ["JNIEnv*", "jintArray", "jsize", "jsize", "jint*"],
    ret: "void",
  },
  {
    name: "SetLongArrayRegion",
    args: ["JNIEnv*", "jlongArray", "jsize", "jsize", "jlong*"],
    ret: "void",
  },
  {
    name: "SetFloatArrayRegion",
    args: ["JNIEnv*", "jfloatArray", "jsize", "jsize", "jfloat*"],
    ret: "void",
  },
  {
    name: "SetDoubleArrayRegion",
    args: ["JNIEnv*", "jdoubleArray", "jsize", "jsize", "jdouble*"],
    ret: "void",
  },
  {
    name: "RegisterNatives",
    args: ["JNIEnv*", "jclass", "JNINativeMethod*", "jint"],
    ret: "jint",
  },
  { name: "UnregisterNatives", args: ["JNIEnv*", "jclass"], ret: "jint" },
  { name: "MonitorEnter", args: ["JNIEnv*", "jobject"], ret: "jint" },
  { name: "MonitorExit", args: ["JNIEnv*", "jobject"], ret: "jint" },
  { name: "GetJavaVM", args: ["JNIEnv*", "JavaVM**"], ret: "jint" },
  {
    name: "GetStringRegion",
    args: ["JNIEnv*", "jstring", "jsize", "jsize", "jchar*"],
    ret: "void",
  },
  {
    name: "GetStringUTFRegion",
    args: ["JNIEnv*", "jstring", "jsize", "jsize", "char*"],
    ret: "void",
  },
  {
    name: "GetPrimitiveArrayCritical",
    args: ["JNIEnv*", "jarray", "jboolean*"],
    ret: "void",
  },
  {
    name: "ReleasePrimitiveArrayCritical",
    args: ["JNIEnv*", "jarray", "void*", "jint"],
    ret: "void",
  },
  {
    name: "GetStringCritical",
    args: ["JNIEnv*", "jstring", "jboolean*"],
    ret: "jchar",
  },
  {
    name: "ReleaseStringCritical",
    args: ["JNIEnv*", "jstring", "jchar*"],
    ret: "void",
  },
  { name: "NewWeakGlobalRef", args: ["JNIEnv*", "jobject"], ret: "jweak" },
  { name: "DeleteWeakGlobalRef", args: ["JNIEnv*", "jweak"], ret: "void" },
  { name: "ExceptionCheck", args: ["JNIEnv*"], ret: "jboolean" },
  {
    name: "NewDirectByteBuffer",
    args: ["JNIEnv*", "void*", "jlong"],
    ret: "jobject",
  },
  { name: "GetDirectBufferAddress", args: ["JNIEnv*", "jobject"], ret: "void" },
  {
    name: "GetDirectBufferCapacity",
    args: ["JNIEnv*", "jobject"],
    ret: "jlong",
  },
  {
    name: "GetObjectRefType",
    args: ["JNIEnv*", "jobject"],
    ret: "jobjectRefType",
  },
];

// JavaVM function table (8 entries, indices 0-7)
const JAVA_VM: MethodDef[] = [
  { name: "reserved0", args: [], ret: "void" },
  { name: "reserved1", args: [], ret: "void" },
  { name: "reserved2", args: [], ret: "void" },
  { name: "DestroyJavaVM", args: ["JavaVM*"], ret: "jint" },
  {
    name: "AttachCurrentThread",
    args: ["JavaVM*", "void**", "void*"],
    ret: "jint",
  },
  { name: "DetachCurrentThread", args: ["JavaVM*"], ret: "jint" },
  { name: "GetEnv", args: ["JavaVM*", "void**", "jint"], ret: "jint" },
  {
    name: "AttachCurrentThreadAsDaemon",
    args: ["JavaVM*", "void**", "void*"],
    ret: "jint",
  },
];

const INT_TYPES = new Set(["jint", "jsize", "jbyte", "jshort"]);

function readValue(type: string, ptr: NativePointer): string {
  try {
    if (type === "char*") {
      if (ptr.isNull()) return "null";
      return ptr.readCString() ?? ptr.toString();
    }
    if (type === "jboolean") {
      return ptr.toInt32() ? "true" : "false";
    }
    if (INT_TYPES.has(type)) {
      return ptr.toInt32().toString();
    }
    return ptr.toString();
  } catch {
    return ptr.toString();
  }
}

function readRet(type: string, ptr: NativePointer): string {
  if (type === "void") return "";
  return readValue(type, ptr);
}

function hookTable(
  fnTable: NativePointer,
  methods: MethodDef[],
  callType: "JNIEnv" | "JavaVM",
) {
  const ptrSize = Process.pointerSize;

  for (let i = 0; i < methods.length; i++) {
    const method = methods[i];
    if (method.name.startsWith("reserved")) continue;

    const fnPtr = fnTable.add(i * ptrSize).readPointer();
    if (fnPtr.isNull()) continue;

    try {
      const m = method;
      const listener = Interceptor.attach(fnPtr, {
        onEnter(args) {
          if (tracingThreads.has(this.threadId)) return;
          tracingThreads.add(this.threadId);
          this._jni = true;

          const parsed: string[] = [];
          // Skip first arg (JNIEnv* / JavaVM*)
          for (let j = 1; j < m.args.length; j++) {
            const type = m.args[j];
            if (type === "..." || type === "va_list") break;
            parsed.push(readValue(type, args[j]));
          }
          this._args = parsed;
          // this._bt = bt(this.context);
        },
        onLeave(retval) {
          if (!this._jni) return;
          tracingThreads.delete(this.threadId);

          send({
            subject,
            type: "trace",
            method: m.name,
            callType,
            threadId: this.threadId,
            args: this._args,
            ret: readRet(m.ret, retval),
            // backtrace: this._bt,
          });
        },
      });
      listeners.push(listener);
    } catch {
      // Some functions may not be interceptable
    }
  }
}

export function available(): boolean {
  return Java.available;
}

export function start(): void {
  if (active) return;
  if (!Java.available) return;

  active = true;

  Java.perform(() => {
    const env = Java.vm.getEnv();
    const envFnTable = env.handle.readPointer();
    hookTable(envFnTable, JNI_ENV, "JNIEnv");

    // Hook JavaVM methods
    try {
      const vmHandle = (Java.vm as unknown as { handle: NativePointer }).handle;
      const vmFnTable = vmHandle.readPointer();
      hookTable(vmFnTable, JAVA_VM, "JavaVM");
    } catch {
      console.warn("jni: could not hook JavaVM methods");
    }

    // Hook dlopen for native library load tracking
    try {
      const dlopen =
        findGlobalExport("android_dlopen_ext") ?? findGlobalExport("dlopen");
      if (dlopen) {
        const listener = Interceptor.attach(dlopen, {
          onEnter(args) {
            this._path = args[0].isNull() ? null : args[0].readCString();
          },
          onLeave() {
            send({
              subject,
              type: "load",
              library: this._path as string,
              method: "dlopen",
              callType: "native",
              threadId: this.threadId,
              args: [this._path],
              ret: "",
            });
          },
        });
        listeners.push(listener);
      }
    } catch {}
  });
}

export function stop(): void {
  for (const listener of listeners) {
    listener.detach();
  }
  listeners = [];
  tracingThreads.clear();
  active = false;
}

export function status(): { active: boolean } {
  return { active };
}
